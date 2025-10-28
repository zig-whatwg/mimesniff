# WHATWG MIME Sniffing - Zig Implementation

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/zig-whatwg/mimesniff)
[![Spec Compliance](https://img.shields.io/badge/spec-100%25-brightgreen)](https://mimesniff.spec.whatwg.org/)
[![Tests](https://img.shields.io/badge/tests-158%20passing-brightgreen)](#testing)

A complete, production-ready implementation of the [WHATWG MIME Sniffing Standard](https://mimesniff.spec.whatwg.org/) in Zig.

## Features

✅ **100% Spec Compliant** - Implements every algorithm from the WHATWG standard  
✅ **Zero Dependencies** (except `infra` standard library)  
✅ **Memory Safe** - Zero leaks, tested with `std.testing.allocator`  
✅ **Fast** - Comptime pattern tables, SIMD optimization, first-byte dispatch  
✅ **Well Tested** - 158 comprehensive tests covering all code paths  
✅ **Browser-Informed** - Optimizations based on Chromium, Firefox, and WebKit research  
✅ **Full Parameter Support** - Handles complex MIME types with multiple parameters

## What is MIME Sniffing?

MIME sniffing is the process of determining the actual content type of a resource by examining its content, rather than blindly trusting the `Content-Type` header. This is critical for:

- **Security** - Preventing XSS attacks from mislabeled content
- **Compatibility** - Handling servers that send incorrect MIME types
- **User Experience** - Displaying content correctly regardless of server configuration

## Installation

Add to your `build.zig.zon`:

```zig
.dependencies = .{
    .mimesniff = .{
        .url = "https://github.com/zig-whatwg/mimesniff/archive/v0.1.0.tar.gz",
        .hash = "...", // zig will provide this
    },
    .infra = .{
        .url = "https://github.com/zig-whatwg/infra/archive/main.tar.gz",
        .hash = "...",
    },
},
```

Add to your `build.zig`:

```zig
const mimesniff = b.dependency("mimesniff", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("mimesniff", mimesniff.module("mimesniff"));
```

## Quick Start

### Basic MIME Type Parsing

```zig
const mimesniff = @import("mimesniff");
const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse a MIME type from a Content-Type header
    var mime = (try mimesniff.parseMimeType(
        allocator,
        "text/html; charset=utf-8"
    )).?;
    defer mime.deinit();

    // Serialize back to string
    const serialized = try mimesniff.serializeMimeTypeToBytes(allocator, mime);
    defer allocator.free(serialized);

    std.debug.print("MIME type: {s}\n", .{serialized});
}
```

### Content Sniffing from HTTP

```zig
const mimesniff = @import("mimesniff");

pub fn sniffHttpResource(
    allocator: std.mem.Allocator,
    content_type_header: ?[]const u8,
    body: []const u8,
) !?mimesniff.MimeType {
    // 1. Determine supplied MIME type from Content-Type header
    var resource = try mimesniff.determineSuppliedMimeType(
        allocator,
        content_type_header
    );
    defer resource.deinit();

    // 2. Read resource header (first 1445 bytes)
    const header = try mimesniff.readResourceHeader(allocator, body);
    defer allocator.free(header);

    // 3. Sniff the MIME type
    const computed = try mimesniff.sniffMimeType(allocator, &resource, header);

    return computed;
}
```

### Content Sniffing from File System

```zig
const mimesniff = @import("mimesniff");

pub fn sniffFile(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    file_content: []const u8,
) !?mimesniff.MimeType {
    // 1. Determine MIME type from file extension
    var resource = try mimesniff.determineSuppliedMimeTypeFromPath(
        allocator,
        file_path
    );
    defer resource.deinit();

    // 2. Read resource header
    const header = try mimesniff.readResourceHeader(allocator, file_content);
    defer allocator.free(header);

    // 3. Sniff the MIME type
    const computed = try mimesniff.sniffMimeType(allocator, &resource, header);

    return computed;
}
```

### Context-Specific Sniffing

```zig
// Sniff in an image context (e.g., <img> tag)
const computed = try mimesniff.sniffInImageContext(
    allocator,
    supplied_mime_type,
    resource_header
);

// Sniff in a script context (e.g., <script> tag)
const computed = try mimesniff.sniffInScriptContext(
    allocator,
    supplied_mime_type,
);

// Other contexts: audio/video, font, style, plugin, text track, cache manifest
```

### MIME Type Predicates

```zig
const mimesniff = @import("mimesniff");

var mime = (try mimesniff.parseMimeType(allocator, "image/png")).?;
defer mime.deinit();

// Check MIME type categories
if (mimesniff.predicates.isImageMimeType(&mime)) {
    std.debug.print("This is an image!\n", .{});
}

// Available predicates:
// - isImageMimeType
// - isAudioOrVideoMimeType
// - isFontMimeType
// - isZipBasedMimeType
// - isArchiveMimeType
// - isXmlMimeType
// - isHtmlMimeType
// - isScriptableMimeType
// - isJavaScriptMimeType
// - isJsonMimeType
```

### Conformance Checking

```zig
const mimesniff = @import("mimesniff");

// Validate MIME type strings
if (mimesniff.isValidMimeTypeString("text/html; charset=utf-8")) {
    std.debug.print("Valid MIME type!\n", .{});
}

// Check for parameters
if (mimesniff.isValidMimeTypeWithNoParameters("text/html")) {
    std.debug.print("No parameters!\n", .{});
}

// Minimize MIME type (for preload spec)
var mime = (try mimesniff.parseMimeType(allocator, "text/javascript1.5")).?;
defer mime.deinit();

const minimized = try mimesniff.minimizeSupportedMimeType(allocator, &mime);
defer allocator.free(minimized);
// Returns "text/javascript"
```

### MIME Type Parameters

The library has **full support** for MIME type parameters, including multiple parameters, quoted values, and structured subtypes (e.g., `+json`, `+xml`).

```zig
const mimesniff = @import("mimesniff");

// Parse MIME type with multiple parameters
var mime = (try mimesniff.parseMimeType(
    allocator,
    "text/html; charset=utf-8; boundary=something"
)).?;
defer mime.deinit();

// Access parameters
const infra = @import("infra");
const entries = mime.parameters.entries.items();
for (entries) |entry| {
    const key = try infra.bytes.isomorphicEncode(allocator, entry.key);
    defer allocator.free(key);
    const value = try infra.bytes.isomorphicEncode(allocator, entry.value);
    defer allocator.free(value);
    
    std.debug.print("{s} = {s}\n", .{key, value});
    // Output:
    // charset = utf-8
    // boundary = something
}

// Structured subtypes with parameters
var custom = (try mimesniff.parseMimeType(
    allocator,
    "text/swiftui+vml;target=ios;charset=UTF-8"
)).?;
defer custom.deinit();

// Round-trip serialization preserves everything
const serialized = try mimesniff.serializeMimeTypeToBytes(allocator, custom);
defer allocator.free(serialized);
// Output: text/swiftui+vml;target=ios;charset=UTF-8
```

**Parameter Features**:
- ✅ Single and multiple parameters
- ✅ Quoted and unquoted values
- ✅ Escape sequences in quoted values (`\"`, `\\`)
- ✅ Whitespace handling (stripped automatically)
- ✅ Parameter name normalization (ASCII lowercase)
- ✅ Parameter value preservation (case-sensitive)
- ✅ Deduplication (first occurrence wins)
- ✅ Ordered map (insertion order preserved)
- ✅ Structured subtypes (`+json`, `+xml`, `+vml`, etc.)

## API Reference

### Core Functions

#### MIME Type Parsing

- `parseMimeType(allocator, bytes: []const u8) !?MimeType`  
  Parse MIME type from UTF-8 bytes (common case: HTTP headers)

- `parseMimeTypeFromString(allocator, string: infra.String) !?MimeType`  
  Parse MIME type from UTF-16 string (Infra spec compliance)

- `serializeMimeType(allocator, mime_type: MimeType) !infra.String`  
  Serialize MIME type to UTF-16 string

- `serializeMimeTypeToBytes(allocator, mime_type: MimeType) ![]const u8`  
  Serialize MIME type to UTF-8 bytes

- `minimizeSupportedMimeType(allocator, mime_type: *const MimeType) ![]const u8`  
  Minimize MIME type for preload specification

#### Conformance Validators

- `isValidMimeTypeString(input: []const u8) bool`  
  Check if string is a valid MIME type

- `isValidMimeTypeWithNoParameters(input: []const u8) bool`  
  Check if string is a valid MIME type with no parameters

#### Resource Handling

- `determineSuppliedMimeType(allocator, content_type: ?[]const u8) !Resource`  
  Determine supplied MIME type from HTTP Content-Type header

- `determineSuppliedMimeTypeFromPath(allocator, file_path: []const u8) !Resource`  
  Determine supplied MIME type from file extension

- `readResourceHeader(allocator, data: []const u8) ![]const u8`  
  Read resource header (first 1445 bytes)

#### Sniffing Algorithms

- `sniffMimeType(allocator, resource: *const Resource, header: []const u8) !?MimeType`  
  Main MIME type sniffing algorithm (§7)

- `sniffInBrowsingContext(allocator, resource: *const Resource, header: []const u8) !?MimeType`  
  Sniff in browsing context (§8.1)

- `identifyUnknownMimeType(allocator, header: []const u8, sniff_scriptable: bool) !?MimeType`  
  Identify resource with unknown MIME type (§7.1)

- `distinguishTextOrBinary(allocator, header: []const u8) !?MimeType`  
  Distinguish if resource is text or binary (§7.2)

#### Context-Specific Sniffing

- `sniffInImageContext(allocator, supplied: ?MimeType, header: []const u8) !?MimeType`
- `sniffInAudioOrVideoContext(allocator, supplied: ?MimeType, header: []const u8) !?MimeType`
- `sniffInFontContext(allocator, supplied: ?MimeType, header: []const u8) !?MimeType`
- `sniffInPluginContext(allocator, supplied: ?MimeType) !?MimeType`
- `sniffInStyleContext(allocator, supplied: ?MimeType) !?MimeType`
- `sniffInScriptContext(allocator, supplied: ?MimeType) !?MimeType`
- `sniffInTextTrackContext(allocator) !?MimeType`
- `sniffInCacheManifestContext(allocator) !?MimeType`

### Predicates

All predicates take `mime_type: *const MimeType` and return `bool`:

- `isImageMimeType` - Type is "image"
- `isAudioOrVideoMimeType` - Type is "audio"/"video" or essence is "application/ogg"
- `isFontMimeType` - Font types
- `isZipBasedMimeType` - Subtype ends with "+zip" or is "application/zip"
- `isArchiveMimeType` - Archive types (ZIP, GZIP, RAR)
- `isXmlMimeType` - Subtype ends with "+xml" or is "text/xml"/"application/xml"
- `isHtmlMimeType` - Essence is "text/html"
- `isScriptableMimeType` - XML, HTML, or PDF
- `isJavaScriptMimeType` - JavaScript MIME types
- `isJsonMimeType` - Subtype ends with "+json" or is "application/json"/"text/json"

## Supported File Types

### Pattern Recognition (Byte-Level Detection)

The library can detect these formats by analyzing byte patterns:

**Images** (9 formats)
- PNG (`\x89PNG`)
- JPEG (`\xFF\xD8\xFF`)
- GIF87a, GIF89a
- WebP (`RIFF????WEBPVP`)
- BMP (`BM`)
- Windows Icon/Cursor (`\x00\x00\x01\x00`, `\x00\x00\x02\x00`)

**Audio/Video** (10 formats)
- MP3 with ID3 (`ID3`)
- MP3 without ID3 (sync word detection)
- MP4 (ftyp box analysis)
- WebM (EBML + DocType check)
- Ogg (`OggS\x00`)
- WAVE (`RIFF????WAVE`)
- AVI (`RIFF????AVI `)
- AIFF (`FORM????AIFF`)
- MIDI (`MThd\x00\x00\x00\x06`)

**Fonts** (6 formats)
- WOFF (`wOFF`)
- WOFF2 (`wOF2`)
- TrueType (`\x00\x01\x00\x00`)
- OpenType (`OTTO`)
- TrueType Collection (`ttcf`)
- Embedded OpenType (34 bytes `\x00` + `LP`)

**Archives** (3 formats)
- GZIP (`\x1F\x8B\x08`)
- ZIP (`PK\x03\x04`)
- RAR (`Rar!\x1A\x07\x00`)

**Documents** (17 HTML patterns + others)
- HTML (17 tag patterns: `<!DOCTYPE HTML`, `<HTML`, `<HEAD`, `<BODY>`, `<SCRIPT>`, `<IFRAME>`, `<H1>`, `<DIV>`, `<FONT>`, `<TABLE>`, `<A>`, `<STYLE>`, `<TITLE>`, `<B>`, `<BR>`, `<P>`, `<!--`)
- XML (`<?xml`)
- PDF (`%PDF-`)
- PostScript (`%!PS-Adobe-`)

### File Extension Mapping (50+ Extensions)

The library maps file extensions to MIME types for file system resources:

**Text Formats**
- `.txt` → `text/plain`
- `.html`, `.htm` → `text/html`
- `.css` → `text/css`
- `.csv` → `text/csv`
- `.xml` → `text/xml`

**JavaScript & JSON**
- `.js`, `.mjs` → `text/javascript`
- `.json` → `application/json`

**Images**
- `.png` → `image/png`
- `.jpg`, `.jpeg` → `image/jpeg`
- `.gif` → `image/gif`
- `.webp` → `image/webp`
- `.svg` → `image/svg+xml`
- `.ico` → `image/x-icon`
- `.bmp` → `image/bmp`

**Audio**
- `.mp3` → `audio/mpeg`
- `.wav` → `audio/wave`
- `.ogg` → `application/ogg`
- `.aiff` → `audio/aiff`
- `.midi`, `.mid` → `audio/midi`

**Video**
- `.mp4` → `video/mp4`
- `.webm` → `video/webm`
- `.avi` → `video/avi`

**Fonts**
- `.woff` → `font/woff`
- `.woff2` → `font/woff2`
- `.ttf` → `font/ttf`
- `.otf` → `font/otf`
- `.eot` → `application/vnd.ms-fontobject`

**Archives**
- `.zip` → `application/zip`
- `.gz` → `application/x-gzip`
- `.rar` → `application/x-rar-compressed`

**Documents**
- `.pdf` → `application/pdf`
- `.ps` → `application/postscript`

**Binary**
- `.bin`, `.exe`, `.dll` → `application/octet-stream`

**Special**
- `.vtt` → `text/vtt` (WebVTT text tracks)
- `.appcache`, `.manifest` → `text/cache-manifest`

## Pattern Matching

The library uses highly optimized pattern matching:

- **Comptime Pattern Tables** - All patterns known at compile time
- **First-Byte Dispatch** - O(1) rejection of impossible patterns (Chromium-style)
- **SIMD Optimization** - Portable SIMD using `@Vector` for 16+ byte patterns
- **Complex Signatures** - MP4, WebM, MP3 without ID3 tag detection

## Testing

Run the test suite:

```bash
zig build test --summary all
```

**Current Status**: 158/158 tests passing, zero memory leaks

## Memory Management

All functions that return allocated memory document ownership in their doc comments. The library uses explicit allocators - no hidden allocations.

**Best Practice**: Use an arena allocator for batch operations:

```zig
var arena = std.heap.ArenaAllocator.init(allocator);
defer arena.deinit();
const temp_allocator = arena.allocator();

// All allocations freed at once
const mime1 = try parseMimeType(temp_allocator, "text/html");
const mime2 = try parseMimeType(temp_allocator, "image/png");
```

## Performance

### Optimizations

1. **Comptime Pattern Generation** - Zero-cost pattern matching
2. **SIMD** - Portable vector operations for long patterns
3. **First-Byte Dispatch** - Inspired by Chromium's implementation
4. **Zero Copies** - Slice-based parsing where possible
5. **UTF-16 Storage** - Spec compliance with V8 interop benefits

### Browser Research

This implementation is informed by deep analysis of:
- **Chromium** - First-byte dispatch, arena allocation
- **Firefox** - SIMD pattern matching (SSE2)
- **WebKit** - State machine for HTML detection

See `analysis/BROWSER_MIME_IMPLEMENTATION_RESEARCH.md` for details.

## Spec Compliance

✅ **100% WHATWG Spec Compliance**

All algorithms from the [WHATWG MIME Sniffing Standard](https://mimesniff.spec.whatwg.org/) are implemented:

- §3 Algorithms
- §4 MIME Types (parsing, serialization, minimization)
- §5 Resource Handling (HTTP, file system)
- §6 Pattern Matching (all formats)
- §7 Computed MIME Type (identification, sniffing)
- §8 Context-Specific Sniffing (all 9 contexts)

## Contributing

Contributions welcome! Please ensure:

1. All tests pass: `zig build test`
2. No memory leaks: Tests use `std.testing.allocator`
3. Spec compliance: Reference WHATWG spec sections in comments
4. Documentation: All public functions have doc comments

## License

This work is dual-licensed:

- **Code**: BSD 3-Clause License
- **Specification**: Creative Commons Attribution 4.0 International License (WHATWG)

See LICENSE file for details.

## Resources

- **WHATWG Spec**: https://mimesniff.spec.whatwg.org/
- **Infra Standard**: https://infra.spec.whatwg.org/
- **Web Platform Tests**: https://github.com/web-platform-tests/wpt/tree/master/mimesniff

## Acknowledgments

This implementation is based on the WHATWG MIME Sniffing Standard, originally developed by Adam Barth, Juan Caballero, and Dawn Song.

Special thanks to the Zig community for the excellent language and tools.

---

**Built with Zig** 🦎
