# WHATWG MIME Sniffing - Zig Implementation Plan

**Version**: 1.0  
**Date**: 2025-01-27  
**Status**: Ready for Implementation

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Architecture Overview](#architecture-overview)
3. [Type System Design](#type-system-design)
4. [Implementation Phases](#implementation-phases)
5. [Browser-Informed Optimizations](#browser-informed-optimizations)
6. [Testing Strategy](#testing-strategy)
7. [Success Criteria](#success-criteria)

---

## Executive Summary

### Project Goal

Implement a complete, spec-compliant Zig library for the **WHATWG MIME Sniffing Standard** that:
- ✅ Uses WHATWG Infra types (UTF-16 strings, ordered maps)
- ✅ Implements all MIME parsing and sniffing algorithms
- ✅ Leverages Zig's strengths (comptime, SIMD, explicit allocators)
- ✅ Matches or exceeds browser performance

### Key Decisions (Informed by Browser Research)

| Aspect | Decision | Rationale |
|--------|----------|-----------|
| **String Storage** | UTF-16 (`infra.String`) | Spec compliance, V8 interop |
| **Parsing Input** | UTF-8 bytes → UTF-16 | Common case (HTTP headers) |
| **Parameters** | `OrderedMap<String, String>` | Spec requires insertion order |
| **Pattern Matching** | Comptime tables + SIMD | Zero cost dispatch, portable |
| **Memory** | Explicit allocator | Caller controls strategy |
| **Optimization** | Comptime constants | Zero-cost string interning |

### Browser Research Summary

**Analyzed**:
- Chromium (Blink) - `net/base/mime_util.cc`, `net/base/mime_sniffer.cc`
- Firefox (Gecko) - `netwerk/mime/`, `dom/security/`
- WebKit - `WebCore/platform/network/ParsedContentType.cpp`

**Key Learnings**:
1. **String views** for zero-copy parsing (all browsers)
2. **First-byte dispatch** for pattern matching (Chromium)
3. **SIMD** for long patterns (Firefox SSE2)
4. **Arena allocation** for batch parsing (Chromium)
5. **Comptime patterns** natural fit for Zig

See `analysis/BROWSER_MIME_IMPLEMENTATION_RESEARCH.md` for full details.

---

## Architecture Overview

### Module Structure

```
src/
├── root.zig              # Public API
├── mime_type.zig         # MIME type struct + parsing/serialization
├── pattern_matching.zig  # Pattern matching algorithms
├── sniffing.zig          # Main sniffing algorithms
├── resource.zig          # Resource metadata + header reading
├── constants.zig         # Byte classification, HTTP tokens
└── predicates.zig        # MIME type predicates (isImage, isAudio, etc.)
```

### Dependency Graph

```
root.zig
  ├── mime_type.zig
  │   ├── constants.zig
  │   └── infra (OrderedMap, String)
  ├── pattern_matching.zig
  │   └── constants.zig
  ├── sniffing.zig
  │   ├── pattern_matching.zig
  │   ├── resource.zig
  │   └── predicates.zig
  └── predicates.zig
      └── mime_type.zig
```

---

## Type System Design

### 1. MIME Type (§3)

**File**: `src/mime_type.zig`

```zig
const std = @import("std");
const infra = @import("infra");

/// MIME type representation per WHATWG Infra §3
/// 
/// Spec: https://mimesniff.spec.whatwg.org/#mime-type
pub const MimeType = struct {
    /// Type (e.g., "text") - ASCII lowercase, UTF-16
    type: infra.String,  // []const u16
    
    /// Subtype (e.g., "html") - ASCII lowercase, UTF-16
    subtype: infra.String,  // []const u16
    
    /// Parameters (e.g., {"charset": "utf-8"}) - ordered, UTF-16 keys/values
    parameters: infra.OrderedMap(infra.String, infra.String),
    
    /// Allocator used for all allocations
    allocator: std.mem.Allocator,
    
    /// Initialize empty MIME type
    pub fn init(allocator: std.mem.Allocator) MimeType {
        return .{
            .type = &[_]u16{},
            .subtype = &[_]u16{},
            .parameters = infra.OrderedMap(infra.String, infra.String).init(allocator),
            .allocator = allocator,
        };
    }
    
    /// Free all allocated memory
    pub fn deinit(self: *MimeType) void {
        self.allocator.free(self.type);
        self.allocator.free(self.subtype);
        
        // Free parameter keys and values
        var it = self.parameters.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key);
            self.allocator.free(entry.value);
        }
        
        self.parameters.deinit();
    }
    
    /// Returns "type/subtype" (essence)
    /// Caller owns returned memory
    pub fn essence(self: MimeType, allocator: std.mem.Allocator) !infra.String {
        const len = self.type.len + 1 + self.subtype.len;
        const result = try allocator.alloc(u16, len);
        
        @memcpy(result[0..self.type.len], self.type);
        result[self.type.len] = '/';
        @memcpy(result[self.type.len + 1..], self.subtype);
        
        return result;
    }
};
```

**Design Rationale**:
- ✅ **Spec-compliant**: Uses Infra types (UTF-16 strings, ordered map)
- ✅ **Explicit allocator**: Caller controls memory strategy
- ✅ **Zero hidden costs**: All allocations visible
- ✅ **RAII pattern**: `deinit()` frees all memory

---

### 2. Parsing Functions

**API Design** (learned from browsers):

```zig
/// Parse MIME type from UTF-8 bytes (common case: HTTP headers)
/// 
/// Per spec §3.4: "To parse a MIME type from bytes"
/// 1. Isomorphic decode bytes → string (UTF-16)
/// 2. Parse MIME type from string
/// 
/// Returns null if parsing fails.
/// Caller owns returned MimeType (must call deinit).
pub fn parseMimeType(
    allocator: std.mem.Allocator,
    input: []const u8,  // UTF-8 bytes
) !?MimeType {
    // Convert UTF-8 → UTF-16 (isomorphic decode per spec)
    const input_utf16 = try infra.bytes.isomorphicDecode(allocator, input);
    defer allocator.free(input_utf16);
    
    return parseMimeTypeFromString(allocator, input_utf16);
}

/// Parse MIME type from Infra string (UTF-16)
/// 
/// Per spec §3.4: "To parse a MIME type"
/// 
/// Returns null if parsing fails.
/// Caller owns returned MimeType (must call deinit).
pub fn parseMimeTypeFromString(
    allocator: std.mem.Allocator,
    input: infra.String,  // UTF-16
) !?MimeType {
    // WHATWG Algorithm (§3.4):
    
    // 1. Remove leading/trailing HTTP whitespace
    const trimmed = stripHttpWhitespace(input);
    if (trimmed.len == 0) return null;
    
    // 2. Let position be a position variable
    var pos: usize = 0;
    
    // 3. Let type be result of collecting sequence NOT U+002F (/)
    const type_end = std.mem.indexOfScalarPos(u16, trimmed, pos, '/') orelse return null;
    const type_slice = trimmed[pos..type_end];
    
    // 4. If type is empty or contains non-HTTP-token code points, return failure
    if (type_slice.len == 0 or !isHttpTokenString(type_slice))
        return null;
    
    // 5. If position is past end, return failure
    if (type_end >= trimmed.len)
        return null;
    
    // 6. Advance position by 1 (skip '/')
    pos = type_end + 1;
    
    // 7. Let subtype be result of collecting sequence NOT U+003B (;)
    const semi_pos = std.mem.indexOfScalarPos(u16, trimmed, pos, ';');
    const subtype_end = semi_pos orelse trimmed.len;
    var subtype_slice = trimmed[pos..subtype_end];
    
    // 8. Remove trailing HTTP whitespace from subtype
    subtype_slice = stripTrailingWhitespace(subtype_slice);
    
    // 9. If subtype is empty or contains non-HTTP-token code points, return failure
    if (subtype_slice.len == 0 or !isHttpTokenString(subtype_slice))
        return null;
    
    // 10. Let mimeType be a new MIME type record
    var mime_type = MimeType.init(allocator);
    errdefer mime_type.deinit();
    
    // Set type (ASCII lowercase)
    mime_type.type = try infra.string.asciiLowercase(allocator, type_slice);
    
    // Set subtype (ASCII lowercase)
    mime_type.subtype = try infra.string.asciiLowercase(allocator, subtype_slice);
    
    // 11. While position is not past end: parse parameters
    if (semi_pos) |semi| {
        pos = semi + 1;
        try parseParameters(allocator, trimmed[pos..], &mime_type.parameters);
    }
    
    // 12. Return mimeType
    return mime_type;
}

/// Helper: Check if all code points are HTTP tokens
fn isHttpTokenString(s: infra.String) bool {
    for (s) |c| {
        if (!isHttpTokenCodePoint(c))
            return false;
    }
    return true;
}

/// Helper: HTTP token code point predicate
fn isHttpTokenCodePoint(c: u16) bool {
    return switch (c) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        '0'...'9', 'A'...'Z', 'a'...'z' => true,
        else => false,
    };
}
```

**Browser-Inspired Optimizations**:
- ✅ **String views** (slices) - No copies during parsing
- ✅ **Early validation** - Reject before allocating
- ✅ **Allocate only for storage** - Parsing is zero-alloc
- ✅ **Error handling** - `errdefer` cleans up on failure

---

### 3. Pattern Matching (§4)

**File**: `src/pattern_matching.zig`

**Comptime Pattern Tables**:

```zig
/// Pattern matching algorithm (WHATWG §4)
pub fn patternMatching(
    input: []const u8,
    pattern: []const u8,
    mask: []const u8,
    ignored: []const u8,
) bool {
    // 1. Assert: pattern.len == mask.len
    std.debug.assert(pattern.len == mask.len);
    
    // 2. If input.len < pattern.len, return false
    if (input.len < pattern.len)
        return false;
    
    // 3-4. Skip ignored bytes at start
    var s: usize = 0;
    while (s < input.len) : (s += 1) {
        if (!std.mem.containsAtLeast(u8, ignored, 1, &[_]u8{input[s]}))
            break;
    }
    
    // 5-6. Match pattern with mask
    var p: usize = 0;
    while (p < pattern.len) : (p += 1) {
        if (s >= input.len)
            return false;
        
        const masked_data = input[s] & mask[p];
        if (masked_data != pattern[p])
            return false;
        
        s += 1;
    }
    
    return true;
}

/// SIMD-optimized matching for long patterns (16+ bytes)
fn patternMatchingSIMD(
    input: []const u8,
    pattern: []const u8,
    mask: []const u8,
) bool {
    if (pattern.len < 16) {
        // Too short for SIMD, use scalar
        return patternMatching(input, pattern, mask, &[_]u8{});
    }
    
    const Vec16 = @Vector(16, u8);
    
    // Load 16 bytes
    const in: Vec16 = input[0..16].*;
    const pat: Vec16 = pattern[0..16].*;
    const msk: Vec16 = mask[0..16].*;
    
    // Apply mask: (input & mask) == (pattern & mask)
    const in_masked = in & msk;
    const pat_masked = pat & msk;
    
    // Compare all 16 bytes at once
    const cmp = in_masked == pat_masked;
    
    // All must match
    return @reduce(.And, cmp);
}
```

**Comptime Pattern Tables** (Browser-inspired first-byte dispatch):

```zig
/// Pattern definition (comptime-known)
pub const Pattern = struct {
    pattern: []const u8,
    mask: []const u8,
    ignored: []const u8,
    mime_type: []const u8,
};

/// Image patterns (comptime constant)
pub const IMAGE_PATTERNS = [_]Pattern{
    // PNG: 89 50 4E 47 0D 0A 1A 0A
    .{
        .pattern = &[_]u8{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
        .mask = &[_]u8{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
        .ignored = &[_]u8{},
        .mime_type = "image/png",
    },
    
    // JPEG: FF D8 FF
    .{
        .pattern = &[_]u8{0xFF, 0xD8, 0xFF},
        .mask = &[_]u8{0xFF, 0xFF, 0xFF},
        .ignored = &[_]u8{},
        .mime_type = "image/jpeg",
    },
    
    // GIF87a / GIF89a
    .{
        .pattern = "GIF87a",
        .mask = &[_]u8{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
        .ignored = &[_]u8{},
        .mime_type = "image/gif",
    },
    .{
        .pattern = "GIF89a",
        .mask = &[_]u8{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
        .ignored = &[_]u8{},
        .mime_type = "image/gif",
    },
    
    // WebP: RIFF????WEBPVP
    .{
        .pattern = "RIFF\x00\x00\x00\x00WEBPVP",
        .mask = &[_]u8{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
        .ignored = &[_]u8{},
        .mime_type = "image/webp",
    },
    
    // BMP: "BM"
    .{
        .pattern = "BM",
        .mask = &[_]u8{0xFF, 0xFF},
        .ignored = &[_]u8{},
        .mime_type = "image/bmp",
    },
    
    // ICO: 00 00 01 00
    .{
        .pattern = &[_]u8{0x00, 0x00, 0x01, 0x00},
        .mask = &[_]u8{0xFF, 0xFF, 0xFF, 0xFF},
        .ignored = &[_]u8{},
        .mime_type = "image/x-icon",
    },
    
    // CUR: 00 00 02 00
    .{
        .pattern = &[_]u8{0x00, 0x00, 0x02, 0x00},
        .mask = &[_]u8{0xFF, 0xFF, 0xFF, 0xFF},
        .ignored = &[_]u8{},
        .mime_type = "image/x-icon",
    },
};

/// First-byte dispatch table (comptime-generated)
/// 
/// Maps first byte → list of candidate patterns
/// Enables O(1) rejection of impossible patterns (Chromium-style)
pub const FIRST_BYTE_DISPATCH = comptime blk: {
    // Initialize 256-entry table
    var table: [256]std.BoundedArray(usize, 32) = undefined;
    for (&table) |*entry| {
        entry.* = std.BoundedArray(usize, 32){};
    }
    
    // Build dispatch table
    for (IMAGE_PATTERNS, 0..) |pattern, idx| {
        const first_byte = pattern.pattern[0];
        table[first_byte].appendAssumeCapacity(idx);
    }
    
    break :blk table;
};

/// Match image type pattern (O(1) dispatch + SIMD)
pub fn matchImageTypePattern(input: []const u8) ?[]const u8 {
    if (input.len == 0)
        return null;
    
    // O(1) first-byte dispatch
    const first_byte = input[0];
    const candidates = FIRST_BYTE_DISPATCH[first_byte];
    
    // Test each candidate pattern
    for (candidates.constSlice()) |idx| {
        const pattern = IMAGE_PATTERNS[idx];
        
        if (patternMatching(input, pattern.pattern, pattern.mask, pattern.ignored)) {
            return pattern.mime_type;
        }
    }
    
    return null;
}
```

**Zig Advantages**:
- ✅ **Comptime tables** - Zero runtime initialization cost
- ✅ **First-byte dispatch** - O(1) rejection (Chromium pattern)
- ✅ **Portable SIMD** - `@Vector` works on all platforms
- ✅ **Type safety** - Compile-time validation of patterns

---

### 4. Resource Metadata (§5)

**File**: `src/resource.zig`

```zig
/// Resource metadata (WHATWG §5)
pub const ResourceMetadata = struct {
    supplied_mime_type: ?MimeType = null,
    check_for_apache_bug: bool = false,
    no_sniff: bool = false,
    computed_mime_type: ?MimeType = null,
};

/// Resource header (up to 1445 bytes per spec §5.1)
pub const ResourceHeader = struct {
    buffer: []const u8,
    
    pub fn init(buffer: []const u8) ResourceHeader {
        return .{ .buffer = buffer };
    }
};

/// Read resource header from reader (§5.1)
/// 
/// Reads up to 1445 bytes (deterministic for sniffing)
pub fn readResourceHeader(
    allocator: std.mem.Allocator,
    reader: anytype,
) !ResourceHeader {
    const max_size = 1445;
    
    var buffer = try std.ArrayList(u8).initCapacity(allocator, max_size);
    errdefer buffer.deinit();
    
    // Read up to max_size bytes
    while (buffer.items.len < max_size) {
        const byte = reader.readByte() catch |err| {
            if (err == error.EndOfStream) break;
            return err;
        };
        try buffer.append(byte);
    }
    
    return ResourceHeader{ .buffer = try buffer.toOwnedSlice() };
}
```

---

## Implementation Phases

### Phase 1: Foundation (Week 1)

**Goal**: Core MIME type parsing and serialization.

**Tasks**:
1. ✅ Set up project structure
2. ✅ Add infra dependency (`build.zig.zon`)
3. ✅ Implement `constants.zig` (byte classification, HTTP token validation)
4. ✅ Implement `MimeType` struct
5. ✅ Implement `parseMimeType` (from UTF-8 bytes)
6. ✅ Implement `parseMimeTypeFromString` (from UTF-16)
7. ✅ Implement `serializeMimeType`
8. ✅ Write comprehensive tests

**Deliverables**:
- `src/constants.zig`
- `src/mime_type.zig`
- `tests/mime_type_test.zig`
- All tests pass with `std.testing.allocator` (no leaks)

**Success Criteria**:
- Parse valid MIME types: `text/html`, `text/html; charset=utf-8`
- Reject invalid MIME types: `text/`, `/html`, empty string
- Handle complex parameters: quoted values, multiple parameters
- Zero memory leaks

---

### Phase 2: Pattern Matching (Week 2)

**Goal**: Implement all pattern matching algorithms with comptime optimization.

**Tasks**:
1. ✅ Implement core `patternMatching()` algorithm
2. ✅ Implement SIMD-optimized variant
3. ✅ Create comptime pattern tables (images, audio/video, fonts, archives)
4. ✅ Implement first-byte dispatch table (comptime)
5. ✅ Implement `matchImageTypePattern()`
6. ✅ Implement `matchAudioOrVideoTypePattern()`
7. ✅ Implement complex signatures: MP4, WebM, MP3
8. ✅ Implement `matchFontTypePattern()`
9. ✅ Implement `matchArchiveTypePattern()`
10. ✅ Write comprehensive tests

**Deliverables**:
- `src/pattern_matching.zig`
- `tests/pattern_matching_test.zig`
- Test fixtures with real byte sequences

**Success Criteria**:
- All pattern tables generated at comptime
- First-byte dispatch works correctly
- SIMD code compiles and runs correctly
- All test fixtures match correctly

---

### Phase 3: MIME Type Predicates (Week 3)

**Goal**: Implement all MIME type classification predicates (§3.6).

**Tasks**:
1. ✅ Implement `isImageMimeType()`
2. ✅ Implement `isAudioOrVideoMimeType()`
3. ✅ Implement `isFontMimeType()`
4. ✅ Implement `isZipBasedMimeType()`
5. ✅ Implement `isArchiveMimeType()`
6. ✅ Implement `isXmlMimeType()`
7. ✅ Implement `isHtmlMimeType()`
8. ✅ Implement `isScriptableMimeType()`
9. ✅ Implement `isJavaScriptMimeType()`
10. ✅ Implement `isJsonMimeType()`
11. ✅ Implement `minimizeSupportedMimeType()`
12. ✅ Write comprehensive tests

**Deliverables**:
- `src/predicates.zig`
- `tests/predicates_test.zig`

**Success Criteria**:
- All predicates match spec requirements
- JavaScript essence match works correctly
- Edge cases handled (subtypes with +xml, +json, +zip)

---

### Phase 4: Sniffing Algorithms (Week 4)

**Goal**: Implement main sniffing algorithms (§6, §7).

**Tasks**:
1. ✅ Implement `identifyUnknownMimeType()` (§6.1)
   - HTML tag detection
   - XML/PDF/PostScript detection
   - BOM detection
   - Image/audio/video/archive fallback
2. ✅ Implement `sniffMislabeledBinary()` (§6.2)
   - BOM detection
   - Binary data byte detection
3. ✅ Implement `determineComputedMimeType()` (§6)
   - XML/HTML early return
   - Unknown MIME type handling
   - no-sniff flag
   - check-for-apache-bug flag
   - Image/audio/video matching
4. ✅ Write comprehensive tests

**Deliverables**:
- `src/sniffing.zig`
- `src/resource.zig`
- `tests/sniffing_test.zig`

**Success Criteria**:
- All sniffing algorithms work correctly
- Scriptable/non-scriptable modes work
- no-sniff flag respected
- Real-world byte sequences sniffed correctly

---

### Phase 5: Context-Specific Sniffing (Week 5)

**Goal**: Implement all 9 context-specific sniffing functions (§8).

**Tasks**:
1. ✅ Implement `sniffInBrowsingContext()` (§8.1)
2. ✅ Implement `sniffInImageContext()` (§8.2)
3. ✅ Implement `sniffInAudioOrVideoContext()` (§8.3)
4. ✅ Implement `sniffInPluginContext()` (§8.4)
5. ✅ Implement `sniffInStyleContext()` (§8.5)
6. ✅ Implement `sniffInScriptContext()` (§8.6)
7. ✅ Implement `sniffInFontContext()` (§8.7)
8. ✅ Implement `sniffInTextTrackContext()` (§8.8)
9. ✅ Implement `sniffInCacheManifestContext()` (§8.9)
10. ✅ Write integration tests

**Deliverables**:
- Context-specific functions in `src/sniffing.zig`
- `tests/integration_test.zig`

**Success Criteria**:
- All context-specific functions work
- Integration tests with realistic scenarios pass
- Full sniffing pipeline works end-to-end

---

### Phase 6: Documentation & Polish (Week 6)

**Goal**: Production-ready documentation and final polish.

**Tasks**:
1. ✅ Write comprehensive inline documentation
   - All public functions documented
   - Spec references in doc comments
   - Usage examples
2. ✅ Write `README.md`
   - Quick start guide
   - API overview
   - Installation instructions
   - Examples
3. ✅ Write `CHANGELOG.md` (Keep a Changelog 1.1.0)
4. ✅ Update `CONTRIBUTING.md`
5. ✅ Update/create `AGENTS.md` (based on infra's)
6. ✅ Performance testing
7. ✅ Final code review

**Deliverables**:
- Complete documentation
- README.md with examples
- CHANGELOG.md (v0.1.0)
- CONTRIBUTING.md
- AGENTS.md

**Success Criteria**:
- All public APIs documented
- README has working examples
- Code quality matches infra standards

---

## Browser-Informed Optimizations

### 1. String Representation (Browsers: UTF-8/UTF-16 mixed)

**Zig Strategy**: UTF-16 for storage (spec-compliant), UTF-8 for input.

```zig
// Storage: UTF-16 (Infra-compliant)
type: infra.String,      // []const u16
subtype: infra.String,   // []const u16

// Parsing: Accept UTF-8 (common case: HTTP headers)
pub fn parseMimeType(allocator: std.mem.Allocator, input: []const u8) !?MimeType;

// Parsing: Accept UTF-16 (for specs that already have UTF-16)
pub fn parseMimeTypeFromString(allocator: std.mem.Allocator, input: infra.String) !?MimeType;
```

**Rationale**: Chromium/Firefox use UTF-8 internally, but WHATWG spec requires UTF-16. We bridge the gap with explicit conversion functions.

---

### 2. Zero-Copy Parsing (Browsers: String views)

**Zig Strategy**: Use slices (string views) during parsing.

```zig
// During parsing: work with slices (zero-copy)
const type_slice = trimmed[0..slash_pos];  // View, no allocation
const subtype_slice = trimmed[slash_pos + 1..semi_pos];  // View, no allocation

// Only allocate for final storage
mime_type.type = try allocator.dupe(u16, type_slice);  // Allocate once
```

**Learned from**: Chromium's `base::StringPiece`, WebKit's `StringView`.

---

### 3. First-Byte Dispatch (Browsers: Chromium)

**Zig Strategy**: Comptime dispatch table.

```zig
// Comptime-generated table: first_byte → candidate patterns
pub const FIRST_BYTE_DISPATCH = comptime buildDispatchTable(IMAGE_PATTERNS);

// O(1) dispatch at runtime
const candidates = FIRST_BYTE_DISPATCH[input[0]];
for (candidates) |pattern_idx| {
    // Test only relevant patterns
}
```

**Learned from**: Chromium's `mime_sniffer.cc` first-byte optimization.

---

### 4. SIMD Pattern Matching (Browsers: Firefox)

**Zig Strategy**: Portable SIMD with `@Vector`.

```zig
const Vec16 = @Vector(16, u8);
const in: Vec16 = input[0..16].*;
const pat: Vec16 = pattern[0..16].*;
const msk: Vec16 = mask[0..16].*;

const in_masked = in & msk;
const pat_masked = pat & msk;
const cmp = in_masked == pat_masked;

return @reduce(.And, cmp);  // All bytes must match
```

**Learned from**: Firefox's SSE2 optimizations, but made portable with Zig's `@Vector`.

---

### 5. Arena Allocation (Browsers: Chromium)

**Zig Strategy**: Explicit allocator parameter (caller chooses).

```zig
// Caller can use arena for batch parsing
var arena = std.heap.ArenaAllocator.init(allocator);
defer arena.deinit();

const mime1 = try parseMimeType(arena.allocator(), "text/html");
const mime2 = try parseMimeType(arena.allocator(), "image/png");
// All freed at once
```

**Learned from**: Chromium's `HeaderArena` for HTTP header parsing.

---

### 6. Comptime String Constants (Browsers: String interning)

**Zig Strategy**: Comptime constants (zero-cost).

```zig
// Common MIME types as comptime constants
pub const TEXT_HTML = "text/html";
pub const IMAGE_PNG = "image/png";
pub const APPLICATION_JSON = "application/json";

// Pointer comparison (zero cost)
if (std.mem.eql(u8, mime_type_bytes, TEXT_HTML)) {
    // Fast path
}
```

**Learned from**: Chromium's `mime_types::kTextHtml` constants, Firefox's atom strings.

---

## Testing Strategy

### Unit Tests (Per Module)

**1. MIME Type Parsing** (`tests/mime_type_test.zig`):
- Valid: `text/html`, `text/html; charset=utf-8`, `application/json`
- Invalid: `text/`, `/html`, `text/html;`, empty, non-token characters
- Parameters: multiple, quoted values, duplicates (last wins), whitespace handling
- Serialization: round-trip, special characters in parameters
- Memory: no leaks with `std.testing.allocator`

**2. Pattern Matching** (`tests/pattern_matching_test.zig`):
- Core algorithm: exact match, mask application, ignored bytes
- Images: PNG, JPEG, GIF, WebP, BMP, ICO
- Audio/video: AIFF, MP3, Ogg, MIDI, AVI, WAVE, MP4, WebM
- Fonts: TrueType, OpenType, WOFF, WOFF2
- Archives: GZIP, ZIP, RAR
- SIMD: 16-byte patterns, mask support
- First-byte dispatch: O(1) rejection

**3. Predicates** (`tests/predicates_test.zig`):
- All `is*MimeType()` functions
- Edge cases: subtypes with +xml, +json, +zip
- JavaScript essence match (case-insensitive)

**4. Sniffing** (`tests/sniffing_test.zig`):
- Unknown type identification (scriptable/non-scriptable)
- Mislabeled binary detection (BOMs, binary bytes)
- no-sniff flag behavior
- check-for-apache-bug flag

### Integration Tests (`tests/integration_test.zig`)

**Realistic scenarios**:
- Parse Content-Type header → MIME type
- Read file bytes → Sniff MIME type
- Full pipeline: HTTP response → Computed MIME type

**Test fixtures**:
- Real file signatures (PNG, JPEG, GIF, PDF, MP3, etc.)
- Real Content-Type headers
- Edge cases (empty, truncated, malformed)

### Memory Safety

**All tests use `std.testing.allocator`**:
```zig
test "no memory leaks" {
    const allocator = std.testing.allocator;
    
    var mime = try parseMimeType(allocator, "text/html");
    defer if (mime) |*m| m.deinit();
    
    // Test passes only if no leaks
}
```

---

## Success Criteria

### Functional Requirements

- ✅ All WHATWG MIME Sniffing algorithms implemented
- ✅ Spec-compliant (uses Infra types)
- ✅ All predicates work correctly
- ✅ All context-specific sniffing works
- ✅ Pattern matching matches all formats

### Quality Requirements

- ✅ Zero memory leaks (verified with `std.testing.allocator`)
- ✅ Full test coverage (unit + integration)
- ✅ Comprehensive documentation (inline + README)
- ✅ Builds with `zig build`
- ✅ All tests pass with `zig build test`

### Performance Requirements

- ✅ Pattern matching uses first-byte dispatch (O(1) rejection)
- ✅ SIMD used for long patterns (16+ bytes)
- ✅ Zero-copy parsing (slices, no intermediate allocations)
- ✅ Comptime pattern tables (zero runtime cost)

### Compatibility Requirements

- ✅ Works with infra library (UTF-16 strings, OrderedMap)
- ✅ Can be used by other WHATWG spec implementations
- ✅ Explicit allocators (caller controls memory)

---

## Open Questions & Decisions

### 1. User Agent Support (`isSupportedByUserAgent`)

**Question**: How to determine if a MIME type is "supported by the user agent"?

**Decision**: **Provide default implementation + customization hook**

```zig
/// Default: Support common web MIME types
pub fn isSupportedByUserAgent(mime_type: MimeType) bool {
    // Check against known list
    return isImageMimeType(mime_type) or
           isAudioOrVideoMimeType(mime_type) or
           isFontMimeType(mime_type) or
           isHtmlMimeType(mime_type) or
           isJavaScriptMimeType(mime_type) or
           isJsonMimeType(mime_type);
}

/// Custom hook (advanced users)
pub fn setSupportedMimeTypeChecker(checker: fn(MimeType) bool) void {
    // Allow custom implementation
}
```

---

### 2. WebIDL Bindings

**Question**: Should we provide WebIDL bindings?

**Decision**: **No, not in Phase 1**

- Mimesniff is a Zig library, not a Web API
- Other specs (Fetch, HTML) will use mimesniff as a Zig dependency
- WebIDL bindings can be added later if needed for zig-js-runtime

---

### 3. CLI Tool

**Question**: Should we include a CLI tool?

**Decision**: **Optional, low priority**

```zig
// src/main.zig (optional)
pub fn main() !void {
    // CLI: sniff MIME type from file
    // zig-out/bin/mimesniff <file>
}
```

Include if time permits, otherwise defer to later release.

---

## Next Steps

1. **Review this plan** - Ensure all requirements captured
2. **Set up project structure** - Create files, add infra dependency
3. **Begin Phase 1** - Implement MIME type parsing
4. **Iterate** - Follow phases, test continuously
5. **Document** - Write docs as we go

---

**Status**: Plan complete. Ready for implementation.

**Estimated Timeline**: 6 weeks (can be accelerated with parallel work)

**Last Updated**: 2025-01-27
