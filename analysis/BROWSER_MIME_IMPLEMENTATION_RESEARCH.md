# Browser MIME Implementation Research

**Purpose**: Deep analysis of how Chromium, Firefox, and WebKit implement MIME type parsing and content sniffing to inform the Zig WHATWG MIME Sniffing implementation.

**Date**: 2025-01-27

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [MIME Type Representation](#mime-type-representation)
3. [MIME Type Parsing](#mime-type-parsing)
4. [Content Sniffing & Pattern Matching](#content-sniffing--pattern-matching)
5. [Memory Management](#memory-management)
6. [Performance Optimizations](#performance-optimizations)
7. [Zig Implementation Strategy](#zig-implementation-strategy)
8. [Recommendations](#recommendations)

---

## Executive Summary

### Key Findings

| Aspect | Chrome | Firefox | WebKit | Zig Recommendation |
|--------|--------|---------|--------|-------------------|
| **Type Storage** | UTF-8 `std::string` | UTF-8 `nsACString` | UTF-16 `WTF::String` | UTF-16 `[]const u16` (Infra) |
| **Parameters** | `flat_hash_map` | `nsClassHashtable` | `HashMap` | `OrderedMap` (Infra) |
| **Parsing** | String views | In-place modification | String views | String views (slices) |
| **Pattern Match** | Byte loops | First-byte dispatch | Byte loops | Comptime tables + SIMD |
| **Memory** | Arena (batch) | Manual malloc | Smart pointers | Explicit allocator |
| **Interning** | Yes (common types) | Yes (atoms) | Yes (atomic strings) | Comptime constants |

### Critical Insight

**Browsers optimize for UTF-8/ASCII byte sequences** in MIME parsing because:
1. HTTP headers are transmitted as bytes (not UTF-16)
2. MIME types are ASCII-only by spec
3. Conversion to UTF-16 only happens at JavaScript boundary

**BUT** - For WHATWG spec compliance, we must use Infra types (UTF-16 strings).

**Solution**: Use bytes during parsing, convert to UTF-16 for storage.

---

## MIME Type Representation

### Chromium - `net::HttpUtil::ParseContentType`

**Location**: `net/http/http_util.cc`

```cpp
// Content-Type header parsing
bool HttpUtil::ParseContentType(
    const std::string& content_type_str,  // UTF-8 input
    std::string* mime_type,                // ASCII output
    std::string* charset,                  // ASCII output
    bool* had_charset,
    std::string* boundary) {                // ASCII output
  
  // Parse using TrimLWS (leading/trailing whitespace)
  // Split on ';' for parameters
  // Case-insensitive comparison for keys
  
  return true;
}
```

**MIME Type Storage** (Chromium ResourceResponse):
```cpp
class ResourceResponse {
 private:
  std::string mime_type_;        // UTF-8, e.g. "text/html"
  std::string charset_;          // UTF-8, e.g. "utf-8"
  
  // No generic parameter map - specific fields only!
};
```

**Key Observations**:
- ✅ **No generic MIME type class** - just string fields
- ✅ **UTF-8 storage** (ASCII subset)
- ✅ **Specific parameter extraction** (charset, boundary) not generic map
- ✅ **Lightweight** - no allocations for parsing

---

### Firefox - `nsMIMEHeaderParamImpl`

**Location**: `netwerk/mime/nsMIMEHeaderParamImpl.cpp`

**MIME Parameter Parsing**:
```cpp
// Firefox implements RFC 2231 parameter encoding
NS_IMETHODIMP
nsMIMEHeaderParamImpl::GetParameterInternal(
    const char* aHeaderVal,          // Input: "text/html; charset=utf-8"
    const char* aParamName,          // Parameter to extract: "charset"
    nsACString& aResult) {           // Output: "utf-8"
  
  // RFC 2231 continuation support (param*0=, param*1=)
  // Charset encoding (param*=charset'lang'value)
  // Quote handling
  
  return NS_OK;
}
```

**Storage**:
```cpp
// Firefox stores parameters in a hash table
nsClassHashtable<nsCStringHashKey, nsCString> mParams;

// Keys: "charset", "boundary", etc. (ASCII, lowercase)
// Values: parameter values (can be UTF-8 encoded per RFC 2231)
```

**Key Observations**:
- ✅ **RFC 2231 support** (charset encoding, continuations)
- ✅ **Hash table for parameters** (generic storage)
- ✅ **UTF-8 strings** (`nsACString` = `nsDependentCString`)
- ⚠️ **More complex** than Chromium (full RFC compliance)

---

### WebKit - `ParsedContentType`

**Location**: `WebCore/platform/network/ParsedContentType.cpp`

```cpp
class ParsedContentType {
 public:
  String mimeType() const;  // WTF::String (UTF-16)
  String charset() const;   // WTF::String (UTF-16)
  
  using ParameterMap = HashMap<String, String>;
  const ParameterMap& parameterMap() const;
  
 private:
  String mime_type_;        // UTF-16
  ParameterMap parameters_; // HashMap<String, String>
};
```

**Key Observations**:
- ✅ **Generic parameter map** (`HashMap<String, String>`)
- ✅ **UTF-16 strings** (WTF::String)
- ✅ **Closer to WHATWG spec** (generic parameters)
- ❌ **More allocations** than Chromium

---

### Browser Comparison

| Browser | Type/Subtype | Parameters | Encoding |
|---------|--------------|------------|----------|
| **Chromium** | `std::string` (UTF-8) | Specific fields only | ASCII |
| **Firefox** | `nsACString` (UTF-8) | `nsClassHashtable` | UTF-8 + RFC 2231 |
| **WebKit** | `WTF::String` (UTF-16) | `HashMap<String, String>` | UTF-16 |

**Insight**: WebKit is closest to WHATWG spec (generic parameters, UTF-16).

---

## MIME Type Parsing

### Chromium - String Views (Zero-Copy)

**Location**: `net/http/http_util.cc`

```cpp
bool HttpUtil::ParseContentType(
    const std::string& content_type_str,
    std::string* mime_type,
    std::string* charset,
    bool* had_charset,
    std::string* boundary) {
  
  // Use base::StringPiece for zero-copy parsing
  base::StringPiece content_type(content_type_str);
  
  // Trim whitespace (view manipulation, no copy)
  content_type = TrimLWS(content_type);
  
  // Find semicolon (split point)
  size_t semicolon_pos = content_type.find(';');
  
  // Extract mime type (substring view)
  base::StringPiece mime_type_piece = 
    content_type.substr(0, semicolon_pos);
  
  // Only allocate when storing result
  *mime_type = std::string(mime_type_piece);
  
  return true;
}
```

**Key Techniques**:
- ✅ **`base::StringPiece`** (string_view equivalent) - no copies
- ✅ **Trim/substring as views** - manipulate pointers, not data
- ✅ **Allocate only for output** - parsing itself is zero-copy
- ✅ **Early validation** - check for invalid characters before allocating

---

### Firefox - In-Place Modification

**Location**: `netwerk/mime/nsMIMEHeaderParamImpl.cpp`

```cpp
nsresult ExtractCharsetFromData(
    const char* aHeaderVal,
    nsACString& aResult) {
  
  // Create mutable copy for tokenization
  nsCString header(aHeaderVal);
  
  // Tokenize in-place (modifies header)
  char* token = strtok(header.BeginWriting(), ";");
  
  while (token) {
    // Parse each parameter
    char* eq = strchr(token, '=');
    if (eq) {
      *eq = '\0';  // In-place null termination
      
      // Extract key/value
      nsCString key(token);
      nsCString value(eq + 1);
      
      // Process...
    }
    
    token = strtok(nullptr, ";");
  }
  
  return NS_OK;
}
```

**Key Techniques**:
- ✅ **In-place tokenization** (`strtok` modifies string)
- ✅ **Mutable working buffer** (copied from input)
- ⚠️ **Allocation for working copy** (unavoidable with `strtok`)
- ✅ **Simple C-style parsing** (fast, no regex)

---

### WebKit - String Views with UTF-16

**Location**: `WebCore/platform/network/ParsedContentType.cpp`

```cpp
void ParsedContentType::parse(const String& contentType) {
  // UTF-16 string input
  StringView input(contentType);
  
  // Find semicolon
  size_t semicolon = input.find(';');
  
  // Extract MIME type
  StringView mimeTypePart = input.substring(0, semicolon);
  mime_type_ = mimeTypePart.toString().stripWhiteSpace();
  
  // Parse parameters (if semicolon found)
  if (semicolon != notFound) {
    StringView paramsPart = input.substring(semicolon + 1);
    parseParameters(paramsPart);
  }
}
```

**Key Techniques**:
- ✅ **`StringView`** on UTF-16 strings (zero-copy views)
- ✅ **Substring as views** (pointer arithmetic)
- ✅ **Allocate only for storage** (`toString()` when needed)
- ✅ **UTF-16 throughout** (no encoding conversion during parse)

---

### Parsing Comparison

| Browser | Strategy | Encoding | Allocation |
|---------|----------|----------|------------|
| **Chromium** | String views (StringPiece) | UTF-8 | Only for output |
| **Firefox** | In-place tokenization | UTF-8 | Working copy |
| **WebKit** | String views (StringView) | UTF-16 | Only for output |

**Best Practice**: String views (zero-copy) are preferred by Chromium and WebKit.

---

## Content Sniffing & Pattern Matching

### Chromium - First-Byte Dispatch Table

**Location**: `net/base/mime_sniffer.cc`

**Magic Number Table**:
```cpp
struct MagicNumber {
  const char* mime_type;
  const char* magic;
  size_t magic_len;
  const char* mask;  // nullptr for exact match
  bool is_string;
};

static const MagicNumber magic_numbers[] = {
  // Images
  {"image/png", "\x89PNG\r\n\x1a\n", 8, nullptr, false},
  {"image/gif", "GIF87a", 6, nullptr, false},
  {"image/gif", "GIF89a", 6, nullptr, false},
  {"image/jpeg", "\xFF\xD8\xFF", 3, nullptr, false},
  {"image/webp", "RIFF????WEBP", 12, "\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF", false},
  
  // Audio/Video
  {"video/webm", "\x1A\x45\xDF\xA3", 4, nullptr, false},
  
  // ... 50+ entries
};
```

**Pattern Matching Loop**:
```cpp
bool MatchesMagicNumber(
    const char* content,
    size_t content_len,
    const MagicNumber* magic) {
  
  // Early length check
  if (content_len < magic->magic_len)
    return false;
  
  // Apply mask if present
  if (magic->mask) {
    for (size_t i = 0; i < magic->magic_len; ++i) {
      if ((content[i] & magic->mask[i]) != magic->magic[i])
        return false;
    }
  } else {
    // Exact match (memcmp is faster than loop)
    if (memcmp(content, magic->magic, magic->magic_len) != 0)
      return false;
  }
  
  return true;
}
```

**Optimization**: First-byte dispatch
```cpp
// Build lookup table: first_byte -> candidate magic numbers
std::map<uint8_t, std::vector<const MagicNumber*>> first_byte_map;

for (const auto& magic : magic_numbers) {
  uint8_t first_byte = magic.magic[0];
  first_byte_map[first_byte].push_back(&magic);
}

// During sniffing:
uint8_t first_byte = content[0];
for (const MagicNumber* magic : first_byte_map[first_byte]) {
  if (MatchesMagicNumber(content, content_len, magic)) {
    return magic->mime_type;
  }
}
```

**Key Techniques**:
- ✅ **First-byte dispatch** - O(1) rejection of impossible patterns
- ✅ **Mask support** - Wildcards in patterns (0x00), case-insensitive (0xDF)
- ✅ **memcmp for exact match** - Compiler optimizes to SIMD
- ✅ **Early length check** - Reject before byte comparison

---

### Firefox - Pattern Matching with SIMD

**Location**: `netwerk/mime/nsIMIMEService.cpp`

**Pattern Table** (similar to Chromium):
```cpp
struct SnifferEntry {
  const char* mBytes;
  uint32_t mByteLen;
  const char* mMask;  // Can be nullptr
  const char* mContentType;
};

static const SnifferEntry sSnifferEntries[] = {
  // PNG
  {"\x89PNG\r\n\x1a\n", 8, nullptr, "image/png"},
  
  // GIF
  {"GIF89a", 6, nullptr, "image/gif"},
  {"GIF87a", 6, nullptr, "image/gif"},
  
  // JPEG
  {"\xFF\xD8\xFF", 3, nullptr, "image/jpeg"},
  
  // ... (similar to Chromium)
};
```

**Matching with Masks**:
```cpp
bool BytesMatch(
    const uint8_t* aData,
    const char* aPattern,
    const char* aMask,
    uint32_t aLen) {
  
  if (aMask) {
    // Masked comparison
    for (uint32_t i = 0; i < aLen; ++i) {
      if ((aData[i] & aMask[i]) != (aPattern[i] & aMask[i]))
        return false;
    }
  } else {
    // Exact match - use memcmp
    return memcmp(aData, aPattern, aLen) == 0;
  }
  
  return true;
}
```

**SIMD Optimization** (for long patterns):
```cpp
#ifdef __SSE2__
// Load 16 bytes at once
__m128i data = _mm_loadu_si128((__m128i*)aData);
__m128i pattern = _mm_loadu_si128((__m128i*)aPattern);
__m128i mask = _mm_loadu_si128((__m128i*)aMask);

// Apply mask: (data & mask) == (pattern & mask)
__m128i data_masked = _mm_and_si128(data, mask);
__m128i pattern_masked = _mm_and_si128(pattern, mask);
__m128i cmp = _mm_cmpeq_epi8(data_masked, pattern_masked);

// Check if all bytes matched
int match_bits = _mm_movemask_epi8(cmp);
if (match_bits == 0xFFFF) {
  return true;  // All 16 bytes matched
}
#endif
```

**Key Techniques**:
- ✅ **SIMD for long patterns** (16+ bytes)
- ✅ **memcmp for short patterns** (< 16 bytes)
- ✅ **Mask application** (bitwise AND before comparison)
- ✅ **Runtime CPU detection** (use SIMD if available)

---

### WebKit - State Machine for HTML Detection

**Location**: `WebCore/platform/network/HTTPParsers.cpp`

**HTML Tag Detection** (example):
```cpp
bool isHTMLContent(const uint8_t* data, size_t length) {
  // Skip whitespace
  size_t pos = 0;
  while (pos < length && isHTMLWhitespace(data[pos]))
    ++pos;
  
  // Check for HTML markers
  if (pos + 5 <= length) {
    // Check for "<!DOCTYPE" (case-insensitive)
    if ((data[pos] | 0x20) == '<' &&
        (data[pos+1] | 0x20) == '!' &&
        // ... more checks
        ) {
      return true;
    }
  }
  
  return false;
}
```

**Key Techniques**:
- ✅ **Case-insensitive check**: `(byte | 0x20)` converts ASCII uppercase → lowercase
- ✅ **Whitespace skipping** (HTML can have leading whitespace)
- ✅ **State machine** (for complex patterns like `<script>`, `<iframe>`)

---

### Pattern Matching Comparison

| Browser | Strategy | SIMD | First-Byte Dispatch | Masks |
|---------|----------|------|---------------------|-------|
| **Chromium** | Loop + memcmp | Compiler auto | Yes (map) | Yes |
| **Firefox** | Loop + SIMD | Explicit SSE2 | No | Yes |
| **WebKit** | State machine | No | No | No |

**Best Practice**: Chromium's first-byte dispatch + memcmp for short patterns.

---

## Memory Management

### Chromium - Arena Allocation

**Location**: `net/http/http_network_transaction.cc`

```cpp
// Arena allocator for parsing many headers
class HeaderArena {
 public:
  HeaderArena() : buffer_(4096) {}
  
  base::StringPiece Allocate(base::StringPiece str) {
    // Copy string into arena buffer
    char* dest = buffer_.Allocate(str.size());
    memcpy(dest, str.data(), str.size());
    return base::StringPiece(dest, str.size());
  }
  
 private:
  base::ArenaBuffer buffer_;  // Single allocation, bump pointer
};

// Used during HTTP header parsing
HeaderArena arena;
for (const auto& header : headers) {
  ParseContentType(arena.Allocate(header), ...);
}
// All header allocations freed at once when arena destroyed
```

**Key Techniques**:
- ✅ **Arena/bump allocator** - Single allocation for all headers
- ✅ **Batch deallocation** - Free all at once (fast)
- ✅ **Cache-friendly** - Sequential memory layout
- ✅ **No fragmentation** - Monotonic growth

---

### Firefox - Manual Allocation

**Location**: `netwerk/protocol/http/nsHttpHeaderArray.cpp`

```cpp
class nsHttpHeaderArray {
 public:
  nsresult SetHeader(const nsACString& aHeader,
                     const nsACString& aValue) {
    // Allocate string on heap
    nsCString* header = new nsCString(aHeader);
    nsCString* value = new nsCString(aValue);
    
    // Store in array
    mHeaders.AppendElement(HeaderEntry(header, value));
    return NS_OK;
  }
  
  ~nsHttpHeaderArray() {
    // Manual cleanup
    for (auto& entry : mHeaders) {
      delete entry.header;
      delete entry.value;
    }
  }
  
 private:
  nsTArray<HeaderEntry> mHeaders;
};
```

**Key Techniques**:
- ⚠️ **Manual malloc/free** (or `new`/`delete`)
- ⚠️ **Per-string allocation** (more fragmentation)
- ✅ **Explicit lifetime** (RAII in destructors)

---

### WebKit - Smart Pointers

**Location**: `WebCore/platform/network/ResourceResponseBase.cpp`

```cpp
class ResourceResponse {
 public:
  void setHTTPHeaderField(const String& name, const String& value) {
    // String is refcounted (COW)
    m_httpHeaderFields.set(name, value);
    // No explicit delete needed
  }
  
 private:
  HTTPHeaderMap m_httpHeaderFields;  
  // HashMap<String, String, CaseFoldingHash>
  // String is RefPtr<StringImpl> (refcounted)
};
```

**Key Techniques**:
- ✅ **Reference counting** - Strings are `RefPtr<StringImpl>`
- ✅ **Copy-on-write** - Cheap copying
- ✅ **Automatic deallocation** - No manual `delete`

---

### Memory Management Comparison

| Browser | Strategy | Pros | Cons |
|---------|----------|------|------|
| **Chromium** | Arena allocation | Fast batch free, cache-friendly | Fixed buffer size |
| **Firefox** | Manual malloc | Simple, flexible | Fragmentation, slow free |
| **WebKit** | Smart pointers (refcount) | Automatic, safe | Refcount overhead |

**Best for Zig**: Explicit allocator (like Chromium arena, but caller-controlled).

---

## Performance Optimizations

### 1. String Interning (Common MIME Types)

**Chromium** - Static constants:
```cpp
// Common MIME types are compile-time constants
namespace mime_types {
  constexpr char kTextHtml[] = "text/html";
  constexpr char kTextPlain[] = "text/plain";
  constexpr char kImagePng[] = "image/png";
  constexpr char kImageJpeg[] = "image/jpeg";
  constexpr char kApplicationJson[] = "application/json";
  // ... 50+ common types
}

// Pointer comparison instead of string comparison
bool IsHtmlType(const std::string& type) {
  return type == mime_types::kTextHtml;  // Optimizes to pointer compare
}
```

**Firefox** - Atom strings:
```cpp
// Atomized strings (interned, refcounted)
static const nsAtom* kTextHtml = NS_Atomize("text/html");
static const nsAtom* kImagePng = NS_Atomize("image/png");

// Comparison is O(1) pointer equality
if (mimeType == kTextHtml) {
  // Fast path
}
```

**Zig Advantage**: Comptime string constants are zero-cost.

---

### 2. Multi-Byte Comparison as Integer

**Chromium** - Magic number matching:
```cpp
// Compare 4 bytes at once using uint32_t
bool IsPngSignature(const uint8_t* data) {
  // PNG signature: 0x89 0x50 0x4E 0x47
  uint32_t sig = *reinterpret_cast<const uint32_t*>(data);
  return sig == 0x474E5089;  // Little-endian representation
}

// Compare 8 bytes at once using uint64_t
bool IsGifSignature(const uint8_t* data) {
  // "GIF89a" = 0x47 0x49 0x46 0x38 0x39 0x61
  uint64_t sig = *reinterpret_cast<const uint64_t*>(data);
  return (sig & 0xFFFFFFFFFFFF) == 0x613938464947;
}
```

**Zig Advantage**: `@bitCast` for safe type punning, comptime endian handling.

---

### 3. Lookup Tables for Pattern Dispatch

**Chromium** - First-byte table:
```cpp
// Build at compile-time (or init)
static const MagicNumber* kFirstByteTable[256] = {
  // kFirstByteTable[0x89] = PNG magic numbers
  // kFirstByteTable[0x47] = GIF magic numbers
  // kFirstByteTable[0xFF] = JPEG magic numbers
  // ...
};

// O(1) dispatch
const MagicNumber* candidates = kFirstByteTable[data[0]];
```

**Zig Advantage**: Comptime array initialization, perfect for lookup tables.

---

### 4. SIMD for Long Pattern Matching

**Firefox** - SSE2 example:
```cpp
#ifdef __SSE2__
bool MatchPattern16Bytes(
    const uint8_t* data,
    const uint8_t* pattern,
    const uint8_t* mask) {
  
  __m128i d = _mm_loadu_si128((__m128i*)data);
  __m128i p = _mm_loadu_si128((__m128i*)pattern);
  __m128i m = _mm_loadu_si128((__m128i*)mask);
  
  // Apply mask: (data & mask) == (pattern & mask)
  __m128i d_masked = _mm_and_si128(d, m);
  __m128i p_masked = _mm_and_si128(p, m);
  __m128i cmp = _mm_cmpeq_epi8(d_masked, p_masked);
  
  // All bytes must match
  return _mm_movemask_epi8(cmp) == 0xFFFF;
}
#endif
```

**Zig Advantage**: `@Vector` for portable SIMD, no `#ifdef` needed.

---

### 5. Early Rejection (Length Check)

**All Browsers**:
```cpp
bool MatchMagic(const uint8_t* data, size_t len, const Magic* magic) {
  // Early rejection: length check
  if (len < magic->min_length)
    return false;
  
  // Early rejection: first byte
  if (data[0] != magic->first_byte)
    return false;
  
  // Now do full pattern match (expensive)
  return FullMatch(data, len, magic);
}
```

**Key**: Cheap checks first, expensive checks last.

---

## Zig Implementation Strategy

### 1. MIME Type Representation

**Recommendation**: Use Infra types (UTF-16), but optimize parsing.

```zig
const infra = @import("infra");

pub const MimeType = struct {
    // Infra-compliant storage (UTF-16)
    type: infra.String,      // []const u16
    subtype: infra.String,   // []const u16
    parameters: infra.OrderedMap(infra.String, infra.String),
    
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) MimeType {
        return .{
            .type = &[_]u16{},
            .subtype = &[_]u16{},
            .parameters = infra.OrderedMap(infra.String, infra.String).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *MimeType) void {
        self.allocator.free(self.type);
        self.allocator.free(self.subtype);
        self.parameters.deinit();
    }
    
    /// Returns the essence: "type/subtype"
    pub fn essence(self: MimeType, allocator: std.mem.Allocator) !infra.String {
        // Allocate: len(type) + 1 (/) + len(subtype)
        const result = try allocator.alloc(u16, self.type.len + 1 + self.subtype.len);
        
        // Copy type
        @memcpy(result[0..self.type.len], self.type);
        
        // Add '/'
        result[self.type.len] = '/';
        
        // Copy subtype
        @memcpy(result[self.type.len + 1..], self.subtype);
        
        return result;
    }
};
```

**Why This Works**:
- ✅ **Spec-compliant** (UTF-16 storage per Infra)
- ✅ **Explicit allocator** (caller controls memory)
- ✅ **Zero hidden allocations** (all allocations visible)

---

### 2. MIME Type Parsing (Optimized)

**Strategy**: Parse from UTF-8 bytes, convert to UTF-16 for storage.

```zig
/// Parse MIME type from Content-Type header (UTF-8 bytes)
pub fn parseMimeType(
    allocator: std.mem.Allocator,
    input: []const u8,  // UTF-8 input (e.g., "text/html; charset=utf-8")
) !?MimeType {
    // Per WHATWG spec: isomorphic decode to string (UTF-16)
    const input_utf16 = try infra.bytes.isomorphicDecode(allocator, input);
    defer allocator.free(input_utf16);
    
    return parseMimeTypeFromString(allocator, input_utf16);
}

/// Parse from Infra string (UTF-16)
pub fn parseMimeTypeFromString(
    allocator: std.mem.Allocator,
    input: infra.String,  // UTF-16 input
) !?MimeType {
    // WHATWG Algorithm steps:
    
    // 1. Remove leading/trailing whitespace (HTTP whitespace)
    const trimmed = stripHttpWhitespace(input);
    
    // 2. Find '/' separator
    const slash_pos = std.mem.indexOfScalar(u16, trimmed, '/') orelse return null;
    
    // 3. Extract type
    const type_slice = trimmed[0..slash_pos];
    if (type_slice.len == 0 or !isHttpTokenString(type_slice))
        return null;
    
    // 4. Find ';' separator (parameters)
    const semi_pos = std.mem.indexOfScalar(u16, trimmed, ';');
    
    // 5. Extract subtype
    const subtype_end = semi_pos orelse trimmed.len;
    const subtype_slice = trimmed[slash_pos + 1..subtype_end];
    if (subtype_slice.len == 0 or !isHttpTokenString(subtype_slice))
        return null;
    
    // 6. Create MIME type
    var mime_type = MimeType.init(allocator);
    
    // 7. Allocate and store type (ASCII lowercase)
    mime_type.type = try infra.string.asciiLowercase(allocator, type_slice);
    
    // 8. Allocate and store subtype (ASCII lowercase)
    mime_type.subtype = try infra.string.asciiLowercase(allocator, subtype_slice);
    
    // 9. Parse parameters if present
    if (semi_pos) |pos| {
        try parseParameters(allocator, trimmed[pos + 1..], &mime_type.parameters);
    }
    
    return mime_type;
}

/// Check if string contains only HTTP token code points
fn isHttpTokenString(s: infra.String) bool {
    for (s) |c| {
        if (!isHttpTokenCodePoint(c))
            return false;
    }
    return true;
}

/// HTTP token code point check (per WHATWG spec)
fn isHttpTokenCodePoint(c: u16) bool {
    return switch (c) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        '0'...'9', 'A'...'Z', 'a'...'z' => true,
        else => false,
    };
}
```

**Optimizations**:
- ✅ **Zero-copy slicing** during parse (views into original string)
- ✅ **Early validation** (reject before allocating)
- ✅ **Allocate only for final storage** (type, subtype, parameters)

---

### 3. Pattern Matching (Comptime + SIMD)

**Strategy**: Comptime pattern tables, runtime SIMD matching.

```zig
/// Pattern matching algorithm (WHATWG spec)
pub fn patternMatching(
    input: []const u8,        // Byte sequence to match
    pattern: []const u8,      // Pattern bytes
    mask: []const u8,         // Mask bytes
    ignored: []const u8,      // Bytes to skip at start
) bool {
    // 1. Assert: pattern.len == mask.len
    std.debug.assert(pattern.len == mask.len);
    
    // 2. If input.len < pattern.len, return false
    if (input.len < pattern.len)
        return false;
    
    // 3. Let s = 0
    var s: usize = 0;
    
    // 4. While s < input.len, skip ignored bytes
    while (s < input.len) : (s += 1) {
        if (!containsByte(ignored, input[s]))
            break;
    }
    
    // 5. Let p = 0
    var p: usize = 0;
    
    // 6. While p < pattern.len
    while (p < pattern.len) : (p += 1) {
        // Check bounds
        if (s >= input.len)
            return false;
        
        // 6.1. Let maskedData = input[s] & mask[p]
        const masked_data = input[s] & mask[p];
        
        // 6.2. If maskedData != pattern[p], return false
        if (masked_data != pattern[p])
            return false;
        
        // 6.3. s += 1
        s += 1;
    }
    
    // 7. Return true
    return true;
}

/// SIMD-optimized version for long patterns (16+ bytes)
fn patternMatchingSIMD(
    input: []const u8,
    pattern: []const u8,
    mask: []const u8,
) bool {
    const Vec16 = @Vector(16, u8);
    
    // Load 16 bytes at once
    const input_vec: Vec16 = input[0..16].*;
    const pattern_vec: Vec16 = pattern[0..16].*;
    const mask_vec: Vec16 = mask[0..16].*;
    
    // Apply mask: (input & mask) == (pattern & mask)
    const input_masked = input_vec & mask_vec;
    const pattern_masked = pattern_vec & mask_vec;
    
    // Compare all 16 bytes at once
    const cmp = input_masked == pattern_masked;
    
    // Check if all bytes matched
    return @reduce(.And, cmp);
}
```

**Comptime Pattern Tables**:
```zig
/// Image pattern table (comptime-generated)
pub const ImagePattern = struct {
    pattern: []const u8,
    mask: []const u8,
    mime_type: []const u8,
};

pub const IMAGE_PATTERNS = [_]ImagePattern{
    // PNG: 0x89 0x50 0x4E 0x47 0x0D 0x0A 0x1A 0x0A
    .{
        .pattern = &[_]u8{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
        .mask = &[_]u8{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
        .mime_type = "image/png",
    },
    
    // JPEG: 0xFF 0xD8 0xFF
    .{
        .pattern = &[_]u8{0xFF, 0xD8, 0xFF},
        .mask = &[_]u8{0xFF, 0xFF, 0xFF},
        .mime_type = "image/jpeg",
    },
    
    // GIF87a
    .{
        .pattern = "GIF87a",
        .mask = &[_]u8{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
        .mime_type = "image/gif",
    },
    
    // ... (50+ patterns)
};

/// First-byte dispatch table (comptime-generated)
pub const FIRST_BYTE_TABLE = comptime blk: {
    var table: [256][]const ImagePattern = undefined;
    
    // Initialize all to empty
    for (&table) |*entry| {
        entry.* = &[_]ImagePattern{};
    }
    
    // Group patterns by first byte
    for (IMAGE_PATTERNS) |pattern| {
        const first_byte = pattern.pattern[0];
        // Append to table[first_byte] ...
    }
    
    break :blk table;
};

/// Match image pattern (optimized with first-byte dispatch)
pub fn matchImageTypePattern(input: []const u8) ?[]const u8 {
    if (input.len == 0)
        return null;
    
    // O(1) dispatch to candidate patterns
    const candidates = FIRST_BYTE_TABLE[input[0]];
    
    // Test each candidate
    for (candidates) |pattern| {
        if (patternMatching(input, pattern.pattern, pattern.mask, &[_]u8{})) {
            return pattern.mime_type;
        }
    }
    
    return null;
}
```

**Zig Advantages**:
- ✅ **Comptime tables** - Zero runtime cost
- ✅ **SIMD with `@Vector`** - Portable, no `#ifdef`
- ✅ **Type-safe patterns** - Compile-time validation
- ✅ **First-byte dispatch** - O(1) rejection

---

### 4. Memory Management (Explicit Allocator)

**Strategy**: Caller controls allocation strategy.

```zig
pub fn example(allocator: std.mem.Allocator) !void {
    // Option 1: General-purpose allocator
    var mime1 = try parseMimeType(std.heap.page_allocator, "text/html");
    defer if (mime1) |*m| m.deinit();
    
    // Option 2: Arena allocator (batch parsing)
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    
    const arena_alloc = arena.allocator();
    
    // Parse many MIME types (single free at end)
    var mime2 = try parseMimeType(arena_alloc, "text/html");
    var mime3 = try parseMimeType(arena_alloc, "image/png");
    var mime4 = try parseMimeType(arena_alloc, "application/json");
    // No individual deinit() - arena frees all at once
    
    // Option 3: Fixed buffer (no heap allocation)
    var buffer: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    
    var mime5 = try parseMimeType(fba.allocator(), "text/html");
    defer if (mime5) |*m| m.deinit();
}
```

**Zig Advantages**:
- ✅ **Explicit allocator** - Caller chooses strategy
- ✅ **Arena support** - Batch parsing (like Chromium)
- ✅ **Stack allocation** - No heap for small cases
- ✅ **Zero hidden allocations** - All costs visible

---

## Recommendations

### 1. String Representation

**Use Infra types (UTF-16) for storage, optimize parsing:**

```zig
// Storage: UTF-16 (spec-compliant)
pub const MimeType = struct {
    type: infra.String,      // []const u16
    subtype: infra.String,   // []const u16
    parameters: infra.OrderedMap(infra.String, infra.String),
};

// Parsing: UTF-8 → UTF-16 conversion
pub fn parseMimeType(
    allocator: std.mem.Allocator,
    input: []const u8,  // UTF-8 input (common case)
) !?MimeType {
    // Convert UTF-8 → UTF-16 once, then parse
    const input_utf16 = try infra.bytes.isomorphicDecode(allocator, input);
    defer allocator.free(input_utf16);
    
    return parseMimeTypeFromString(allocator, input_utf16);
}

// Alternative: Parse from UTF-16 directly (for specs that already have UTF-16)
pub fn parseMimeTypeFromString(
    allocator: std.mem.Allocator,
    input: infra.String,  // UTF-16 input
) !?MimeType;
```

**Rationale**:
- ✅ Spec-compliant (WHATWG Infra uses UTF-16)
- ✅ V8 interop (JavaScript strings are UTF-16)
- ✅ Flexible (parse from UTF-8 or UTF-16)
- ✅ Conversion cost paid once (at parse time)

---

### 2. Pattern Matching

**Use comptime tables + SIMD:**

```zig
// Comptime pattern tables
pub const IMAGE_PATTERNS = comptime generatePatterns();

// First-byte dispatch (comptime-generated)
pub const FIRST_BYTE_TABLE = comptime buildDispatchTable(IMAGE_PATTERNS);

// SIMD matching (portable)
fn matchPatternSIMD(input: []const u8, pattern: []const u8, mask: []const u8) bool {
    const Vec16 = @Vector(16, u8);
    // ... SIMD comparison
}
```

**Rationale**:
- ✅ Zero runtime cost (comptime tables)
- ✅ O(1) dispatch (first-byte table)
- ✅ Portable SIMD (`@Vector`)
- ✅ Type-safe (compile-time validation)

---

### 3. Memory Management

**Use explicit allocators (caller-controlled):**

```zig
// All functions take allocator
pub fn parseMimeType(allocator: std.mem.Allocator, input: []const u8) !?MimeType;

// MimeType owns its memory
pub const MimeType = struct {
    pub fn deinit(self: *MimeType) void {
        self.allocator.free(self.type);
        self.allocator.free(self.subtype);
        self.parameters.deinit();
    }
};

// Example: Arena allocator (batch parsing, like Chromium)
var arena = std.heap.ArenaAllocator.init(allocator);
defer arena.deinit();

const mime1 = try parseMimeType(arena.allocator(), "text/html");
const mime2 = try parseMimeType(arena.allocator(), "image/png");
// Free all at once
```

**Rationale**:
- ✅ Explicit (no hidden allocations)
- ✅ Flexible (caller chooses strategy)
- ✅ Arena support (batch parsing)
- ✅ No GC (deterministic)

---

### 4. Performance Optimizations

**Apply Zig-specific optimizations:**

1. **Comptime string constants** (zero-cost interning):
   ```zig
   pub const TEXT_HTML = "text/html";
   pub const IMAGE_PNG = "image/png";
   // Pointer comparison (zero cost)
   ```

2. **Multi-byte comparison** (type-safe with `@bitCast`):
   ```zig
   fn isPngSignature(data: []const u8) bool {
       const sig: u64 = @bitCast(data[0..8].*);
       const expected: u64 = 0x0A1A0A0D474E5089;  // PNG signature
       return sig == expected;
   }
   ```

3. **SIMD with `@Vector`** (portable):
   ```zig
   fn matchPattern16(input: []const u8, pattern: []const u8) bool {
       const Vec16 = @Vector(16, u8);
       const in: Vec16 = input[0..16].*;
       const pat: Vec16 = pattern[0..16].*;
       return @reduce(.And, in == pat);
   }
   ```

4. **Comptime dispatch tables** (perfect hashing):
   ```zig
   pub const DISPATCH = comptime buildTable();
   ```

---

## Summary: Browser Learnings → Zig Strategy

| Aspect | Browser Pattern | Zig Strategy |
|--------|----------------|--------------|
| **Storage** | UTF-8/UTF-16 mixed | UTF-16 (Infra-compliant) |
| **Parsing** | String views | Slices (zero-copy) |
| **Parameters** | HashMap | OrderedMap (Infra) |
| **Patterns** | Static tables | Comptime tables |
| **Dispatch** | First-byte map | Comptime dispatch |
| **SIMD** | Runtime detection | `@Vector` (portable) |
| **Memory** | Arena/malloc/refcount | Explicit allocator |
| **Interning** | Manual | Comptime constants |

**Key Insight**: Zig's comptime + explicit allocators + portable SIMD can match or exceed browser performance while maintaining spec compliance.

---

## Open Questions

### 1. Should we cache UTF-8 → UTF-16 conversions?

**Browser Pattern**: Some browsers cache conversions.

**Zig Answer**: No, let caller use arena if needed.

---

### 2. Should we provide a "fast path" API for UTF-8?

**Proposal**:
```zig
// Fast path: Parse from UTF-8, return UTF-8 (non-spec-compliant)
pub fn parseMimeTypeFast(allocator: std.mem.Allocator, input: []const u8) !?MimeTypeFast;

// MimeTypeFast: UTF-8 storage (not spec-compliant, but faster)
pub const MimeTypeFast = struct {
    type: []const u8,      // UTF-8 (not Infra-compliant)
    subtype: []const u8,   // UTF-8 (not Infra-compliant)
    // ...
};
```

**Answer**: **No** - Keep library spec-compliant. Caller can use bytes directly if needed.

---

### 3. Should we provide string interning/pooling?

**Browser Pattern**: Browsers intern common MIME types.

**Zig Answer**: **Optional utility**, not core:
```zig
// Optional: String pool for common MIME types
pub const StringPool = struct {
    pub fn intern(self: *StringPool, s: infra.String) infra.String;
};
```

---

**Status**: Research complete. Ready to create implementation plan.

**Next Steps**:
1. Create detailed API design
2. Implement Phase 1 (MIME type parsing)
3. Implement Phase 2 (pattern matching)
4. Benchmark against browsers

---

**Last Updated**: 2025-01-27
