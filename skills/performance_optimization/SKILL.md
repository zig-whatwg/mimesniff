# Performance Optimization Skill

## When to use this skill

Load when implementing or optimizing:
- List and map operations
- String operations and validation
- JSON parsing and serialization
- Base64 encoding and decoding
- Hot paths in Infra primitives
- Memory allocation patterns

## What this skill provides

Infra-specific performance optimization strategies:
- Fast paths for common cases (ASCII, small sizes)
- Allocation minimization patterns
- Cache-friendly data structures
- Early exit conditions
- String operation optimization
- JSON parsing optimization
- Base64 encoding optimization

## Critical: Performance Matters (But Spec Compliance First)

**Infra is the foundation for other specs. Performance matters, but correctness is priority #1.**

Infra primitives are used heavily by DOM, Fetch, URL, and other specs. Optimizations are valuable, but **never sacrifice spec compliance for speed**.

**Optimization Priority**:
1. ✅ Spec compliance (must be correct)
2. ✅ Memory safety (no leaks, no UB)
3. ✅ Performance (optimize within constraints)

---

## Fast Paths for Common Cases

### ASCII Fast Path for Strings

Most strings in web standards are pure ASCII. Optimize for this.

```zig
// ✅ GOOD: Fast path for ASCII (most common case)
pub fn asciiLowercase(allocator: Allocator, string: []const u8) ![]u8 {
    // Fast path: pure ASCII check
    var is_ascii = true;
    for (string) |byte| {
        if (byte >= 0x80) {
            is_ascii = false;
            break;
        }
    }
    
    if (is_ascii) {
        // Fast ASCII-only path (no UTF-8 decoding)
        const result = try allocator.alloc(u8, string.len);
        for (string, 0..) |byte, i| {
            if (byte >= 'A' and byte <= 'Z') {
                result[i] = byte + 0x20; // Simple arithmetic
            } else {
                result[i] = byte;
            }
        }
        return result;
    }
    
    // Slow path: Unicode string (rare)
    return try unicodeLowercase(allocator, string);
}

// ❌ BAD: Always using slow path
pub fn asciiLowercase(allocator: Allocator, string: []const u8) ![]u8 {
    // Always decodes UTF-8, even for ASCII!
    return try unicodeLowercase(allocator, string);
}
```

### Small Size Fast Path

Optimize for small lists/maps which are common in specs.

```zig
// ✅ GOOD: Linear search for small sets, hash for large
pub const OrderedSet = struct {
    items: std.ArrayList(T),
    
    pub fn contains(self: OrderedSet, item: T) bool {
        // Small set: linear search is faster (cache-friendly)
        if (self.items.items.len < 8) {
            for (self.items.items) |existing| {
                if (std.mem.eql(u8, existing, item)) return true;
            }
            return false;
        }
        
        // Large set: would benefit from hash map
        // But Infra spec requires ordered set, so linear is correct
        for (self.items.items) |existing| {
            if (std.mem.eql(u8, existing, item)) return true;
        }
        return false;
    }
};
```

---

## Minimize Allocations

### Reuse Buffers Across Operations

```zig
// ✅ GOOD: Reuse buffer across iterations
pub fn processStrings(allocator: Allocator, strings: [][]const u8) ![][]u8 {
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    var results = std.ArrayList([]u8).init(allocator);
    errdefer {
        for (results.items) |item| allocator.free(item);
        results.deinit();
    }
    
    for (strings) |string| {
        buffer.clearRetainingCapacity(); // Reuse allocation!
        
        // Process into buffer...
        try stripNewlines(buffer, string);
        
        // Save result
        try results.append(try buffer.toOwnedSlice());
    }
    
    return results.toOwnedSlice();
}

// ❌ BAD: Allocate per iteration
pub fn processStrings(allocator: Allocator, strings: [][]const u8) ![][]u8 {
    var results = std.ArrayList([]u8).init(allocator);
    errdefer {
        for (results.items) |item| allocator.free(item);
        results.deinit();
    }
    
    for (strings) |string| {
        var buffer = std.ArrayList(u8).init(allocator); // New allocation each time!
        defer buffer.deinit();
        
        try stripNewlines(buffer, string);
        try results.append(try buffer.toOwnedSlice());
    }
    
    return results.toOwnedSlice();
}
```

### Stack Allocation for Small, Fixed Buffers

```zig
// ✅ GOOD: Stack allocation for small, fixed-size buffers
pub fn formatCodePoint(code_point: u21) [8]u8 {
    var buffer: [8]u8 = undefined;
    const len = std.unicode.utf8Encode(code_point, &buffer) catch unreachable;
    return buffer;
}

// For larger or dynamic buffers, use allocator
pub fn encodeCodePoints(allocator: Allocator, code_points: []u21) ![]u8 {
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    for (code_points) |cp| {
        var utf8_buf: [4]u8 = undefined;
        const len = try std.unicode.utf8Encode(cp, &utf8_buf);
        try buffer.appendSlice(utf8_buf[0..len]);
    }
    
    return buffer.toOwnedSlice();
}
```

### Preallocate When Size Known

```zig
// ✅ GOOD: Preallocate when size is known
pub fn parseJsonArray(allocator: Allocator, json_array: std.json.Array) !std.ArrayList(InfraValue) {
    // We know the final size!
    var list = try std.ArrayList(InfraValue).initCapacity(allocator, json_array.items.len);
    errdefer {
        for (list.items) |item| item.deinit(allocator);
        list.deinit();
    }
    
    for (json_array.items) |item| {
        const value = try convertJsonValue(allocator, item);
        list.appendAssumeCapacity(value); // No reallocation!
    }
    
    return list;
}

// ❌ BAD: Let ArrayList grow incrementally
pub fn parseJsonArray(allocator: Allocator, json_array: std.json.Array) !std.ArrayList(InfraValue) {
    var list = std.ArrayList(InfraValue).init(allocator);
    // Will reallocate multiple times as it grows
    
    for (json_array.items) |item| {
        const value = try convertJsonValue(allocator, item);
        try list.append(value);
    }
    
    return list;
}
```

---

## Cache-Friendly Data Structures

### Contiguous Memory for Lists

```zig
// ✅ GOOD: Use ArrayList for cache-friendly sequential access
pub fn sumList(list: std.ArrayList(u32)) u64 {
    var sum: u64 = 0;
    for (list.items) |value| {
        // Cache-friendly: items are contiguous in memory
        sum += value;
    }
    return sum;
}
```

### OrderedMap Implementation

For ordered maps, we need to preserve insertion order. Two approaches:

```zig
// Approach 1: Parallel arrays (cache-friendly for iteration)
pub const OrderedMap = struct {
    keys: std.ArrayList([]const u8),
    values: std.ArrayList(Value),
    
    // Iteration is cache-friendly (sequential access)
    pub fn iterate(self: OrderedMap) Iterator {
        return .{ .map = self, .index = 0 };
    }
    
    // Lookup is O(n) but cache-friendly for small maps
    pub fn get(self: OrderedMap, key: []const u8) ?Value {
        for (self.keys.items, 0..) |k, i| {
            if (std.mem.eql(u8, k, key)) {
                return self.values.items[i];
            }
        }
        return null;
    }
};

// Approach 2: Array of entries (better for small maps)
pub const OrderedMap = struct {
    entries: std.ArrayList(Entry),
    
    const Entry = struct {
        key: []const u8,
        value: Value,
    };
    
    // Most cache-friendly: key and value together
    pub fn get(self: OrderedMap, key: []const u8) ?Value {
        for (self.entries.items) |entry| {
            // Key and value in same cache line
            if (std.mem.eql(u8, entry.key, key)) {
                return entry.value;
            }
        }
        return null;
    }
};
```

**When to use which**:
- **Parallel arrays**: When values are large (> 64 bytes)
- **Array of entries**: When entries are small (< 64 bytes) - better cache locality

---

## Early Exit Conditions

Check cheapest conditions first.

```zig
// ✅ GOOD: Check cheapest conditions first
pub fn validateString(string: []const u8) !void {
    // 1. Check length first (cheapest - just a usize)
    if (string.len == 0) {
        return error.EmptyString;
    }
    
    // 2. Check for invalid bytes (moderate cost)
    for (string) |byte| {
        if (byte < 0x20 and byte != '\t' and byte != '\n' and byte != '\r') {
            return error.InvalidControlCharacter;
        }
    }
    
    // 3. Validate UTF-8 (most expensive)
    if (!std.unicode.utf8ValidateSlice(string)) {
        return error.InvalidUtf8;
    }
}

// ❌ BAD: Check expensive conditions first
pub fn validateString(string: []const u8) !void {
    // Validate UTF-8 even if string is empty!
    if (!std.unicode.utf8ValidateSlice(string)) {
        return error.InvalidUtf8;
    }
    
    if (string.len == 0) {
        return error.EmptyString; // Should check this first!
    }
}
```

---

## String Operation Optimization

### Avoid Unnecessary Allocations

```zig
// ✅ GOOD: Check if work is needed first
pub fn stripNewlines(allocator: Allocator, string: []const u8) ![]u8 {
    // Fast check: does string contain newlines?
    var has_newlines = false;
    for (string) |byte| {
        if (byte == '\n' or byte == '\r') {
            has_newlines = true;
            break;
        }
    }
    
    // If no newlines, return copy without processing
    if (!has_newlines) {
        return try allocator.dupe(u8, string);
    }
    
    // Only process if needed
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();
    
    for (string) |byte| {
        if (byte != '\n' and byte != '\r') {
            try result.append(byte);
        }
    }
    
    return result.toOwnedSlice();
}
```

### String Interning for Repeated Strings

```zig
// For specs that process many repeated strings (namespaces, common keys)
pub const StringPool = struct {
    map: std.StringHashMap([]const u8),
    allocator: Allocator,
    
    pub fn intern(self: *StringPool, string: []const u8) ![]const u8 {
        // Check if already interned
        if (self.map.get(string)) |interned| {
            return interned; // Return existing (no allocation!)
        }
        
        // Allocate and store
        const owned = try self.allocator.dupe(u8, string);
        try self.map.put(owned, owned);
        return owned;
    }
};

// Example usage in namespace URIs (Infra §8)
const HTML_NAMESPACE = "http://www.w3.org/1999/xhtml";
const SVG_NAMESPACE = "http://www.w3.org/2000/svg";
// etc.

// These can be compared by pointer instead of byte-by-byte
pub fn isHtmlNamespace(ns: []const u8) bool {
    return ns.ptr == HTML_NAMESPACE.ptr or std.mem.eql(u8, ns, HTML_NAMESPACE);
}
```

---

## JSON Parsing Optimization

### Preallocate for Known Structure

```zig
// ✅ GOOD: Preallocate when parsing JSON arrays
pub fn parseJsonArray(allocator: Allocator, json: []const u8) !std.ArrayList(InfraValue) {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();
    
    const array = parsed.value.array;
    
    // Preallocate - we know the size!
    var result = try std.ArrayList(InfraValue).initCapacity(allocator, array.items.len);
    errdefer {
        for (result.items) |item| item.deinit(allocator);
        result.deinit();
    }
    
    for (array.items) |item| {
        const value = try convertJsonValue(allocator, item);
        result.appendAssumeCapacity(value);
    }
    
    return result;
}
```

### Avoid Redundant Conversions

```zig
// ✅ GOOD: Convert once, store result
pub fn parseJsonToInfraValue(allocator: Allocator, json: []const u8) !InfraValue {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();
    
    // Convert once
    return try convertJsonValue(allocator, parsed.value);
}

// ❌ BAD: Parsing JSON string multiple times
pub fn processJson(allocator: Allocator, json: []const u8) !void {
    const value1 = try parseJsonToInfraValue(allocator, json); // Parse 1
    defer value1.deinit(allocator);
    
    const value2 = try parseJsonToInfraValue(allocator, json); // Parse 2 (redundant!)
    defer value2.deinit(allocator);
}
```

---

## Base64 Optimization

### Remove Whitespace Efficiently

```zig
// ✅ GOOD: Count first, allocate once
pub fn removeAsciiWhitespace(allocator: Allocator, string: []const u8) ![]u8 {
    // Count non-whitespace characters
    var count: usize = 0;
    for (string) |byte| {
        if (byte != ' ' and byte != '\t' and byte != '\n' and byte != '\r' and byte != '\x0C') {
            count += 1;
        }
    }
    
    // Allocate exact size needed
    const result = try allocator.alloc(u8, count);
    errdefer allocator.free(result);
    
    // Copy non-whitespace
    var i: usize = 0;
    for (string) |byte| {
        if (byte != ' ' and byte != '\t' and byte != '\n' and byte != '\r' and byte != '\x0C') {
            result[i] = byte;
            i += 1;
        }
    }
    
    return result;
}

// ❌ BAD: ArrayList grows incrementally
pub fn removeAsciiWhitespace(allocator: Allocator, string: []const u8) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();
    
    for (string) |byte| {
        if (byte != ' ' and byte != '\t' and byte != '\n' and byte != '\r' and byte != '\x0C') {
            try result.append(byte); // May reallocate multiple times
        }
    }
    
    return result.toOwnedSlice();
}
```

### Lookup Tables for Validation

```zig
// ✅ GOOD: Lookup table for base64 character validation
const base64_lookup = blk: {
    var table: [256]bool = [_]bool{false} ** 256;
    // A-Z
    for ('A'..'Z' + 1) |c| table[c] = true;
    // a-z
    for ('a'..'z' + 1) |c| table[c] = true;
    // 0-9
    for ('0'..'9' + 1) |c| table[c] = true;
    // + and /
    table['+'] = true;
    table['/'] = true;
    break :blk table;
};

pub fn isBase64Char(byte: u8) bool {
    return base64_lookup[byte]; // O(1) lookup
}

// ❌ BAD: Range checks for every character
pub fn isBase64Char(byte: u8) bool {
    return (byte >= 'A' and byte <= 'Z') or
           (byte >= 'a' and byte <= 'z') or
           (byte >= '0' and byte <= '9') or
           byte == '+' or
           byte == '/';
}
```

---

## Inline Hot Paths

```zig
// Inline small, frequently called functions
pub inline fn isAscii(byte: u8) bool {
    return byte < 0x80;
}

pub inline fn isAsciiWhitespace(byte: u8) bool {
    return byte == ' ' or byte == '\t' or byte == '\n' or byte == '\r' or byte == '\x0C';
}

pub inline fn isAsciiAlpha(byte: u8) bool {
    return (byte >= 'A' and byte <= 'Z') or (byte >= 'a' and byte <= 'z');
}

// Don't inline large or cold functions
pub fn parseComplexJson(allocator: Allocator, json: []const u8) !InfraValue {
    // Large function - don't inline
    // ...
}
```

---

## Performance Testing

### Measure Before Optimizing

```zig
test "performance - string operations" {
    const allocator = std.testing.allocator;
    const iterations = 10000;
    const test_string = "Hello, World!\n\rTest string with newlines\n\r";
    
    var timer = try std.time.Timer.start();
    
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        const result = try stripNewlines(allocator, test_string);
        defer allocator.free(result);
    }
    
    const elapsed = timer.read();
    const ns_per_op = elapsed / iterations;
    
    std.debug.print("stripNewlines: {} ns/op\n", .{ns_per_op});
    
    // Assert reasonable performance
    try std.testing.expect(ns_per_op < 10_000); // Must be < 10μs
}
```

### Compare Implementations

```bash
# Run tests in ReleaseFast mode to measure real performance
zig build test -Doptimize=ReleaseFast

# Use --summary to see performance test output
zig build test -Doptimize=ReleaseFast --summary all
```

---

## Common Performance Patterns

### Lazy Initialization

```zig
// Initialize only when needed
pub const OrderedMap = struct {
    entries: ?std.ArrayList(Entry) = null,
    allocator: Allocator,
    
    pub fn ensureInitialized(self: *OrderedMap) !void {
        if (self.entries == null) {
            self.entries = std.ArrayList(Entry).init(self.allocator);
        }
    }
};
```

### Copy-on-Write for Immutable Data

```zig
// Share read-only data, copy only when modifying
pub const ImmutableList = struct {
    data: []const T,
    is_owned: bool,
    
    pub fn makeMutable(self: *ImmutableList, allocator: Allocator) ![]T {
        if (!self.is_owned) {
            const owned = try allocator.dupe(T, self.data);
            self.data = owned;
            self.is_owned = true;
        }
        // Safe to return mutable because we own it
        return @constCast(self.data);
    }
};
```

### Small String Optimization

```zig
// Store small strings inline to avoid allocation
pub const SmallString = union(enum) {
    small: struct {
        buf: [23]u8,
        len: u8,
    },
    large: []const u8,
    
    pub fn fromSlice(allocator: Allocator, s: []const u8) !SmallString {
        if (s.len <= 23) {
            var buf: [23]u8 = undefined;
            @memcpy(buf[0..s.len], s);
            return .{ .small = .{ .buf = buf, .len = @intCast(s.len) } };
        } else {
            const owned = try allocator.dupe(u8, s);
            return .{ .large = owned };
        }
    }
    
    pub fn slice(self: SmallString) []const u8 {
        return switch (self) {
            .small => |s| s.buf[0..s.len],
            .large => |s| s,
        };
    }
};
```

---

## Performance Verification

**⚠️ CRITICAL: ALWAYS use -Doptimize=ReleaseFast for performance testing!**

Debug builds are 10-100x slower and do not represent real performance.

```bash
# ✅ CORRECT: Always use ReleaseFast for performance testing
zig build test -Doptimize=ReleaseFast

# ❌ WRONG: Debug mode results are meaningless
zig build test  # This runs in Debug mode
```

---

## Integration with Other Skills

This skill coordinates with:
- **whatwg_compliance** - Ensure optimizations don't break spec compliance
- **zig_standards** - Use Zig idioms for optimal performance
- **testing_requirements** - Performance tests to catch regressions

**Load all relevant skills for complete optimization guidance.**

---

## Key Takeaways

1. **Spec compliance first** - Never sacrifice correctness for speed
2. **Fast paths for common cases** - ASCII strings, small sizes
3. **Minimize allocations** - Reuse buffers, preallocate when size known
4. **Cache-friendly structures** - Contiguous memory for sequential access
5. **Early exit** - Check cheapest conditions first
6. **Measure before optimizing** - Use ReleaseFast builds for accurate measurement
7. **Inline hot paths** - Small, frequently called functions
8. **String interning** - For repeated strings (namespaces, common keys)

**Remember**: Infra is the foundation. Optimizations are valuable, but spec compliance is non-negotiable.
