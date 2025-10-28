# WHATWG Infra Specification Compliance Skill

## When to use this skill

Load this skill automatically when:
- Implementing Infra algorithms or data structures
- Understanding Infra type definitions
- Verifying spec compliance for primitives
- Mapping Infra types to Zig types
- Checking algorithm correctness

## What this skill provides

This skill contains the complete, authoritative WHATWG Infra specification - NOT fragments or grep results. Read specifications holistically to understand:

- Complete algorithm specifications with all steps
- Data structure definitions and operations
- Primitive type definitions and constraints
- Edge cases documented in related sections
- Cross-references between algorithms

---

## What is the WHATWG Infra Standard?

### Official Specification

**URL**: https://infra.spec.whatwg.org/

**Purpose**: "The Infra Standard aims to define the fundamental concepts upon which standards are built."

### Scope

The Infra Standard defines:

1. **§3 Algorithms** - Algorithm declaration patterns, control flow, assertions
2. **§4 Primitive Data Types** - Nulls, booleans, numbers, bytes, strings, code points
3. **§5 Data Structures** - Lists, ordered maps, ordered sets, stacks, queues, structs, tuples
4. **§6 JSON** - Parsing and serialization between JSON and Infra values
5. **§7 Forgiving Base64** - Forgiving encoding and decoding
6. **§8 Namespaces** - HTML, MathML, SVG, XLink, XML, XMLNS namespace URIs

### What Infra Does NOT Define

❌ **NO DOM** - No nodes, elements, documents, tree structures
❌ **NO HTML** - No HTML-specific parsing or semantics
❌ **NO Web APIs** - No browser interfaces or behaviors
❌ **NO Domain Logic** - Pure primitives only

### Why Infra Matters

Infra is the **foundation layer** for web specifications:
- **DOM Standard** uses Infra lists, strings, and algorithms
- **Fetch Standard** uses Infra maps, bytes, and JSON
- **URL Standard** uses Infra strings, code points, and parsing algorithms

**Precision is critical**: If Infra deviates from spec, dependent specs break.

---

## Infra → Zig Type Mapping

### Core Principle

Map Infra types to **idiomatic Zig** equivalents that preserve Infra semantics.

### Primitive Types (§4)

| Infra Type | Zig Type | Notes | Spec Reference |
|------------|----------|-------|----------------|
| `null` | `null` | Absence of value | §4.1 |
| `boolean` | `bool` | true/false | §4.2 |
| `8-bit unsigned integer` | `u8` | 0 to 255 | §4.3 |
| `16-bit unsigned integer` | `u16` | 0 to 65535 | §4.3 |
| `32-bit unsigned integer` | `u32` | 0 to 4294967295 | §4.3 |
| `64-bit unsigned integer` | `u64` | 0 to 2^64-1 | §4.3 |
| `8-bit signed integer` | `i8` | -128 to 127 | §4.3 |
| `16-bit signed integer` | `i16` | -32768 to 32767 | §4.3 |
| `32-bit signed integer` | `i32` | -2^31 to 2^31-1 | §4.3 |
| `64-bit signed integer` | `i64` | -2^63 to 2^63-1 | §4.3 |
| `byte` | `u8` | 0x00 to 0xFF | §4.4 |
| `byte sequence` | `[]const u8` | Sequence of bytes | §4.5 |
| `code point` | `u21` | U+0000 to U+10FFFF | §4.6 |
| `string` | `[]const u8` | UTF-8 encoded | §4.7 |
| `ASCII string` | `[]const u8` | Only ASCII code points | §4.7 |
| `isomorphic string` | `[]const u8` | U+0000 to U+00FF | §4.7 |
| `scalar value string` | `[]const u8` | No surrogates | §4.7 |

### Data Structures (§5)

| Infra Type | Zig Type | Implementation | Spec Reference |
|------------|----------|----------------|----------------|
| `list` | `std.ArrayList(T)` | Standard library | §5.1 |
| `stack` | `std.ArrayList(T)` | List with push/pop | §5.1.1 |
| `queue` | `std.ArrayList(T)` | List with enqueue/dequeue | §5.1.2 |
| `ordered set` | `OrderedSet(T)` | Custom (no duplicates, preserves order) | §5.1.3 |
| `ordered map` | `OrderedMap(K, V)` | Custom (preserves insertion order) | §5.2 |
| `struct` | `struct { ... }` | Zig struct with named fields | §5.3 |
| `tuple` | `struct { ... }` | Zig struct (fields accessed by index) | §5.3.1 |

**Important**: `ordered map` and `ordered set` require **custom implementations** because Zig's stdlib HashMap doesn't preserve insertion order.

---

## Infra Algorithm Patterns

### Algorithm Declaration (§3.3)

**Infra Pattern**:
```
To [algorithm name], given a [type1] [parameter1], a [type2] [parameter2], …,
perform the following steps. They return a [return type].
```

**Zig Pattern**:
```zig
/// [Brief description of algorithm purpose]
///
/// Implements WHATWG Infra "[algorithm name]" per §X.Y.
///
/// ## Spec Reference
/// https://infra.spec.whatwg.org/#[section-anchor]
///
/// ## Algorithm (Infra §X.Y)
/// [Paste complete algorithm from spec]
///
/// ## Parameters
/// - `param1`: [Type and description]
/// - `param2`: [Type and description]
///
/// ## Returns
/// [Description of return value]
pub fn algorithmName(param1: Type1, param2: Type2) ReturnType {
    // 1. [First algorithm step from spec]
    // 2. [Second algorithm step from spec]
    // ...
}
```

### Example: List Append (§5.1)

**Infra Spec**:
> To append to a list that is not an ordered set is to add the given item to the end of the list.

**Zig Implementation**:
```zig
/// Appends an item to the end of a list.
///
/// Implements WHATWG Infra "append" operation per §5.1.
///
/// ## Spec Reference
/// https://infra.spec.whatwg.org/#list-append
///
/// ## Algorithm (Infra §5.1)
/// To append to a list that is not an ordered set is to add the given 
/// item to the end of the list.
///
/// ## Parameters
/// - `list`: The list to append to (mutable)
/// - `item`: The item to append
///
/// ## Returns
/// Error if allocation fails, otherwise void.
pub fn append(list: *std.ArrayList(T), item: T) !void {
    // To append to a list is to add the given item to the end of the list.
    try list.append(item);
}
```

### Example: Ordered Map Set (§5.2)

**Infra Spec**:
> To set the value of an entry in an ordered map to a given value is to update the value of any 
> existing entry if the map contains an entry with the given key, or if none such exists, to add 
> a new entry with the given key/value to the end of the map.

**Zig Implementation**:
```zig
/// Sets the value of an entry in an ordered map.
///
/// Implements WHATWG Infra "set" operation per §5.2.
///
/// ## Spec Reference
/// https://infra.spec.whatwg.org/#map-set
///
/// ## Algorithm (Infra §5.2)
/// To set the value of an entry in an ordered map to a given value is to 
/// update the value of any existing entry if the map contains an entry with 
/// the given key, or if none such exists, to add a new entry with the given 
/// key/value to the end of the map.
///
/// ## Parameters
/// - `map`: The ordered map (mutable)
/// - `key`: The key (must match key type K)
/// - `value`: The value to set
///
/// ## Returns
/// Error if allocation fails, otherwise void.
pub fn set(map: *OrderedMap(K, V), key: K, value: V) !void {
    // 1. If map contains key, update existing entry
    if (map.getIndex(key)) |index| {
        map.values.items[index] = value;
        return;
    }
    
    // 2. Otherwise, add new entry to end
    try map.keys.append(key);
    try map.values.append(value);
}
```

---

## String Operations (§4.7)

Infra defines many string operations. These are **critical** for spec compliance.

### ASCII Lowercase (§4.7)

**Infra Spec**:
> To ASCII lowercase a string, replace all ASCII upper alphas in the string with their corresponding code point in ASCII lower alpha.

**Zig Implementation**:
```zig
/// Converts ASCII uppercase letters to lowercase.
///
/// Implements WHATWG Infra "ASCII lowercase" per §4.7.
///
/// ## Spec Reference
/// https://infra.spec.whatwg.org/#ascii-lowercase
///
/// ## Algorithm (Infra §4.7)
/// To ASCII lowercase a string, replace all ASCII upper alphas in the string 
/// with their corresponding code point in ASCII lower alpha.
///
/// ## Parameters
/// - `allocator`: Allocator for result string
/// - `string`: Input string
///
/// ## Returns
/// New string with ASCII uppercase converted to lowercase.
pub fn asciiLowercase(allocator: Allocator, string: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, string.len);
    errdefer allocator.free(result);
    
    for (string, 0..) |byte, i| {
        // ASCII upper alpha: U+0041 (A) to U+005A (Z)
        // ASCII lower alpha: U+0061 (a) to U+007A (z)
        // Difference: 0x20
        if (byte >= 'A' and byte <= 'Z') {
            result[i] = byte + 0x20;
        } else {
            result[i] = byte;
        }
    }
    
    return result;
}
```

### Strip Newlines (§4.7)

**Infra Spec**:
> To strip newlines from a string, remove any U+000A LF and U+000D CR code points from the string.

**Zig Implementation**:
```zig
/// Removes newline characters from a string.
///
/// Implements WHATWG Infra "strip newlines" per §4.7.
///
/// ## Spec Reference
/// https://infra.spec.whatwg.org/#strip-newlines
///
/// ## Algorithm (Infra §4.7)
/// To strip newlines from a string, remove any U+000A LF and U+000D CR 
/// code points from the string.
///
/// ## Parameters
/// - `allocator`: Allocator for result string
/// - `string`: Input string
///
/// ## Returns
/// New string with newlines removed.
pub fn stripNewlines(allocator: Allocator, string: []const u8) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();
    
    for (string) |byte| {
        // Skip U+000A LF and U+000D CR
        if (byte != '\n' and byte != '\r') {
            try result.append(byte);
        }
    }
    
    return result.toOwnedSlice();
}
```

---

## JSON Operations (§6)

Infra defines algorithms for converting between JSON and Infra values.

### JSON → Infra Value

**Infra defines these value types**:
- Null → `null`
- Boolean → `bool`
- Number → `f64` (JavaScript numbers are IEEE 754 doubles)
- String → `[]const u8`
- Array → `list` of Infra values
- Object → `ordered map` (string keys to Infra values)

**Zig Representation**:
```zig
pub const InfraValue = union(enum) {
    null_value: void,
    boolean: bool,
    number: f64,
    string: []const u8,
    list: std.ArrayList(InfraValue),
    map: OrderedMap([]const u8, InfraValue),
    
    pub fn deinit(self: InfraValue, allocator: Allocator) void {
        switch (self) {
            .string => |s| allocator.free(s),
            .list => |*l| {
                for (l.items) |item| {
                    item.deinit(allocator);
                }
                l.deinit();
            },
            .map => |*m| {
                for (m.values.items) |item| {
                    item.deinit(allocator);
                }
                m.deinit();
            },
            else => {},
        }
    }
};
```

### Parse JSON String to Infra Value (§6)

**Zig Implementation** (simplified - actual would use Zig's JSON parser):
```zig
/// Parses a JSON string into an Infra value.
///
/// Implements WHATWG Infra "parse JSON string to Infra value" per §6.
///
/// ## Spec Reference
/// https://infra.spec.whatwg.org/#parse-a-json-string-to-an-infra-value
///
/// ## Algorithm (Infra §6)
/// 1. Let jsValue be ? Call(%JSON.parse%, undefined, « string »).
/// 2. Return the result of converting a JSON-derived JavaScript value to 
///    an Infra value, given jsValue.
///
/// ## Parameters
/// - `allocator`: Allocator for Infra value
/// - `json_string`: JSON string to parse
///
/// ## Returns
/// Infra value, or error if JSON is invalid.
pub fn parseJsonStringToInfraValue(
    allocator: Allocator,
    json_string: []const u8,
) !InfraValue {
    // Use Zig's std.json parser
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        allocator,
        json_string,
        .{},
    );
    defer parsed.deinit();
    
    return try convertJsonValueToInfraValue(allocator, parsed.value);
}

fn convertJsonValueToInfraValue(
    allocator: Allocator,
    json_value: std.json.Value,
) !InfraValue {
    switch (json_value) {
        .null => return .{ .null_value = {} },
        .bool => |b| return .{ .boolean = b },
        .integer => |i| return .{ .number = @floatFromInt(i) },
        .float => |f| return .{ .number = f },
        .number_string => |s| {
            const f = try std.fmt.parseFloat(f64, s);
            return .{ .number = f };
        },
        .string => |s| {
            const copy = try allocator.dupe(u8, s);
            return .{ .string = copy };
        },
        .array => |arr| {
            var list = std.ArrayList(InfraValue).init(allocator);
            errdefer {
                for (list.items) |item| {
                    item.deinit(allocator);
                }
                list.deinit();
            }
            
            for (arr.items) |item| {
                const infra_item = try convertJsonValueToInfraValue(allocator, item);
                try list.append(infra_item);
            }
            
            return .{ .list = list };
        },
        .object => |obj| {
            var map = OrderedMap([]const u8, InfraValue).init(allocator);
            errdefer {
                for (map.values.items) |item| {
                    item.deinit(allocator);
                }
                map.deinit();
            }
            
            var iter = obj.iterator();
            while (iter.next()) |entry| {
                const key = try allocator.dupe(u8, entry.key_ptr.*);
                const value = try convertJsonValueToInfraValue(allocator, entry.value_ptr.*);
                try map.set(key, value);
            }
            
            return .{ .map = map };
        },
    }
}
```

---

## Base64 Operations (§7)

### Forgiving Base64 Decode (§7)

**Infra Spec** (simplified):
> 1. Remove all ASCII whitespace from data.
> 2. If data's code point length divides by 4 leaving no remainder:
>    - If data ends with one or two U+003D (=) code points, remove them.
> 3. If data's code point length divides by 4 leaving a remainder of 1, return failure.
> 4. If data contains a code point that is not one of:
>    - U+002B (+), U+002F (/), ASCII alphanumeric
>    then return failure.
> 5. [Decode using base64 alphabet]

**Zig Implementation** (simplified):
```zig
/// Decodes a base64 string with forgiving error handling.
///
/// Implements WHATWG Infra "forgiving-base64 decode" per §7.
///
/// ## Spec Reference
/// https://infra.spec.whatwg.org/#forgiving-base64-decode
///
/// ## Parameters
/// - `allocator`: Allocator for output bytes
/// - `data`: Base64 string to decode
///
/// ## Returns
/// Decoded byte sequence, or error if invalid base64.
pub fn forgivingBase64Decode(
    allocator: Allocator,
    data: []const u8,
) ![]u8 {
    // 1. Remove all ASCII whitespace from data
    const cleaned = try removeAsciiWhitespace(allocator, data);
    defer allocator.free(cleaned);
    
    var working = cleaned;
    
    // 2. If length divides by 4 with no remainder, remove trailing '='
    if (working.len % 4 == 0) {
        if (working.len >= 2 and 
            working[working.len - 1] == '=' and 
            working[working.len - 2] == '=') {
            working = working[0..working.len - 2];
        } else if (working.len >= 1 and working[working.len - 1] == '=') {
            working = working[0..working.len - 1];
        }
    }
    
    // 3. If length divides by 4 leaving remainder of 1, return error
    if (working.len % 4 == 1) {
        return error.InvalidBase64;
    }
    
    // 4. Validate characters
    for (working) |byte| {
        if (!isBase64Char(byte)) {
            return error.InvalidBase64;
        }
    }
    
    // 5. Decode using standard base64 (use std.base64)
    const decoder = std.base64.standard.Decoder;
    const max_size = try decoder.calcSizeForSlice(working);
    const output = try allocator.alloc(u8, max_size);
    errdefer allocator.free(output);
    
    const decoded_len = try decoder.decode(output, working);
    return allocator.realloc(output, decoded_len);
}

fn isBase64Char(byte: u8) bool {
    return (byte >= 'A' and byte <= 'Z') or
           (byte >= 'a' and byte <= 'z') or
           (byte >= '0' and byte <= '9') or
           byte == '+' or
           byte == '/';
}

fn removeAsciiWhitespace(allocator: Allocator, string: []const u8) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();
    
    for (string) |byte| {
        // ASCII whitespace: U+0009 TAB, U+000A LF, U+000C FF, U+000D CR, U+0020 SPACE
        if (byte != '\t' and byte != '\n' and byte != '\x0C' and 
            byte != '\r' and byte != ' ') {
            try result.append(byte);
        }
    }
    
    return result.toOwnedSlice();
}
```

---

## Implementation Workflow

### Step 1: Read Complete Infra Section

**NEVER use grep**. Open the full spec:
- https://infra.spec.whatwg.org/

Find your section (e.g., §5.1 Lists) and read:
1. **Section introduction** - Understand context and purpose
2. **ALL algorithm steps** - Don't skip any steps
3. **Related algorithms** - Cross-references matter
4. **Examples** - Show expected behavior

### Step 2: Map Types to Zig

Use the type mapping table in this skill:
- Identify input types
- Identify output types
- Identify intermediate types
- Choose appropriate Zig types

### Step 3: Implement Algorithm Precisely

**Follow spec steps exactly**:
```zig
pub fn algorithmName(...) !ReturnType {
    // 1. [First step from spec - use numbered comment]
    
    // 2. [Second step from spec]
    
    // 3. [Third step from spec]
    
    // Return [what spec says to return]
}
```

### Step 4: Document with Spec References

**Required documentation**:
1. Brief description
2. "Implements WHATWG Infra [algorithm] per §X.Y"
3. Spec reference URL
4. Complete algorithm (paste from spec)
5. Parameter descriptions
6. Return value description

### Step 5: Test Thoroughly

Write tests for:
- Happy path (normal case)
- Edge cases (empty, boundary values)
- Error cases (invalid input)
- Memory safety (no leaks with std.testing.allocator)

---

## Verification Checklist

Before marking any implementation complete:

- [ ] Read **complete** Infra section (not grep snippet)
- [ ] Read **all algorithm steps** (don't skip any)
- [ ] Checked type mapping (Infra → Zig)
- [ ] Implemented all steps precisely (numbered comments)
- [ ] Tested happy path, edge cases, errors
- [ ] No memory leaks (verified with std.testing.allocator)
- [ ] Documentation includes spec reference URL
- [ ] Documentation includes complete algorithm from spec
- [ ] Code matches spec behavior exactly

---

## Common Mistakes to Avoid

### ❌ Mistake 1: Using Grep

```bash
# WRONG
rg "ASCII lowercase" /path/to/spec

# RIGHT
# Open https://infra.spec.whatwg.org/#ascii-lowercase
# Read complete section with context
```

### ❌ Mistake 2: Wrong Type Mapping

```zig
// WRONG: Using HashMap for ordered map (doesn't preserve order!)
pub const OrderedMap = std.StringHashMap(Value);

// RIGHT: Custom implementation that preserves insertion order
pub const OrderedMap = struct {
    keys: std.ArrayList([]const u8),
    values: std.ArrayList(Value),
    // Preserves order!
};
```

### ❌ Mistake 3: Incomplete Algorithm

```zig
// WRONG: Only implementing first step
pub fn stripNewlines(allocator: Allocator, string: []const u8) ![]u8 {
    // Oops, only removes \n, not \r!
    var result = std.ArrayList(u8).init(allocator);
    for (string) |byte| {
        if (byte != '\n') try result.append(byte);
    }
    return result.toOwnedSlice();
}

// RIGHT: Following spec completely
pub fn stripNewlines(allocator: Allocator, string: []const u8) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    for (string) |byte| {
        // Spec: "remove any U+000A LF and U+000D CR"
        if (byte != '\n' and byte != '\r') {
            try result.append(byte);
        }
    }
    return result.toOwnedSlice();
}
```

### ❌ Mistake 4: Missing Documentation

```zig
// WRONG: No spec reference
pub fn append(list: *ArrayList(T), item: T) !void {
    try list.append(item);
}

// RIGHT: Complete documentation
/// Appends an item to a list.
///
/// Implements WHATWG Infra "append" per §5.1.
///
/// ## Spec Reference
/// https://infra.spec.whatwg.org/#list-append
///
/// ## Algorithm (Infra §5.1)
/// To append to a list that is not an ordered set is to add the given 
/// item to the end of the list.
pub fn append(list: *ArrayList(T), item: T) !void {
    try list.append(item);
}
```

---

## Best Practices

1. **Read complete sections** - Context prevents bugs
2. **Number comments match spec steps** - Makes verification easy
3. **Paste algorithm into docs** - Ensures you don't miss steps
4. **Test with spec examples** - If spec has examples, test them
5. **Check cross-references** - Spec often references related algorithms
6. **Use exact terminology** - If spec says "ordered map", don't call it "map"

---

## Integration with Other Skills

This skill coordinates with:
- **zig_standards** - Provides Zig idioms for implementing algorithms
- **testing_requirements** - Defines how to test spec compliance
- **documentation_standards** - Format for spec references in docs
- **performance_optimization** - When to optimize beyond spec requirements

Load all relevant skills together for complete implementation guidance.

---

## Quick Reference

### Finding Algorithms in Spec

```
https://infra.spec.whatwg.org/

§3 Algorithms        - How to write algorithms
§4 Primitive types   - Nulls, booleans, numbers, bytes, strings
§5 Data structures   - Lists, maps, sets, stacks, queues, structs
§6 JSON              - JSON ↔ Infra value conversion
§7 Base64            - Forgiving base64 encoding/decoding
§8 Namespaces        - Namespace URI constants
```

### Type Mapping Quick Lookup

```
list            → ArrayList(T)
ordered map     → OrderedMap(K, V)      (custom!)
ordered set     → OrderedSet(T)         (custom!)
string          → []const u8
byte sequence   → []const u8
boolean         → bool
null            → null
code point      → u21
byte            → u8
```

### Algorithm Template

```zig
/// [Brief description]
///
/// Implements WHATWG Infra "[name]" per §X.Y.
///
/// ## Spec Reference
/// https://infra.spec.whatwg.org/#[anchor]
///
/// ## Algorithm (Infra §X.Y)
/// [Paste complete algorithm]
///
/// ## Parameters
/// - `param`: Description
///
/// ## Returns
/// Description of return value
pub fn name(param: Type) !ReturnType {
    // 1. [First step]
    // 2. [Second step]
    // ...
}
```

---

**Remember**: Infra is the foundation. Precision matters. Other specs depend on it being correct.
