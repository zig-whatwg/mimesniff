# Documentation Standards Skill

## When to use this skill

Load when:
- Writing inline documentation for public APIs
- Updating README.md
- Maintaining CHANGELOG.md
- Documenting design decisions
- Creating completion reports

## What this skill provides

Documentation standards for Infra implementation:
- Module-level documentation format (`//!` comments)
- Function and type documentation (`///` comments)
- Infra specification references
- Usage examples with primitives
- README.md update workflow
- CHANGELOG.md format (Keep a Changelog 1.1.0)

---

## Module-Level Documentation (`//!`)

**Every file MUST start with comprehensive module-level documentation using `//!` comments.**

### Structure

```zig
//! [Title] - [Brief Description]
//!
//! [Detailed overview paragraph explaining what this module implements from Infra]
//!
//! ## WHATWG Infra Specification
//!
//! Relevant specification sections:
//! - **§X.Y [Section Name]**: https://infra.spec.whatwg.org/#section
//! - **§X.Z [Related Section]**: https://infra.spec.whatwg.org/#related
//!
//! ## Core Features
//!
//! ### [Feature Category 1]
//! [Description of feature with code example]
//! ```zig
//! var list = std.ArrayList(u8).init(allocator);
//! defer list.deinit();
//! try list.append(42);
//! ```
//!
//! ### [Feature Category 2]
//! [Description with code example]
//!
//! ## Usage Examples
//!
//! ### [Common Use Case 1]
//! ```zig
//! const result = try operation(allocator, input);
//! defer allocator.free(result);
//! ```
//!
//! ## Performance Considerations
//!
//! [Details about performance characteristics, if applicable]
//!
//! ## Memory Management
//!
//! [Details about allocation patterns and cleanup]
```

### Example: List Operations

```zig
//! List Operations - WHATWG Infra §5.1
//!
//! Implements list data structure and operations from the Infra Standard.
//! Lists are ordered collections that can contain duplicate values.
//!
//! ## WHATWG Infra Specification
//!
//! Relevant specification sections:
//! - **§5.1 Lists**: https://infra.spec.whatwg.org/#lists
//! - **§5.1.1 Stacks**: https://infra.spec.whatwg.org/#stacks
//! - **§5.1.2 Queues**: https://infra.spec.whatwg.org/#queues
//!
//! ## Core Features
//!
//! ### Append
//! Add an item to the end of a list.
//! ```zig
//! var list = std.ArrayList(u8).init(allocator);
//! defer list.deinit();
//! try list.append(42);
//! ```
//!
//! ### Prepend
//! Add an item to the beginning of a list.
//! ```zig
//! try list.insert(0, 10);
//! ```
//!
//! ### Remove
//! Remove an item at a specific index.
//! ```zig
//! const removed = list.orderedRemove(0);
//! ```
//!
//! ### Iteration
//! Process each item in the list.
//! ```zig
//! for (list.items) |item| {
//!     // Process item
//! }
//! ```
//!
//! ## Implementation Notes
//!
//! Lists are implemented using Zig's `std.ArrayList(T)` which provides:
//! - Dynamic resizing (amortized O(1) append)
//! - Contiguous memory (cache-friendly iteration)
//! - Type safety at compile time
//!
//! ## Memory Management
//!
//! Lists require explicit deinitialization:
//! ```zig
//! var list = std.ArrayList(u8).init(allocator);
//! defer list.deinit(); // Required - frees allocated memory
//! ```
```

---

## Function Documentation (`///`)

### Public Functions

**Every public function MUST have documentation.**

```zig
/// [Brief one-line description].
///
/// Implements WHATWG Infra "[operation name]" per §X.Y.
///
/// [Detailed explanation of what the function does, how it works, and any 
/// important behavioral notes]
///
/// ## Spec Reference
///
/// https://infra.spec.whatwg.org/#[anchor]
///
/// ## Algorithm (Infra §X.Y)
///
/// [Paste the complete algorithm from the spec, or summarize steps]
///
/// ## Parameters
///
/// - `param1`: Description of first parameter
/// - `param2`: Description of second parameter
///
/// ## Returns
///
/// Description of return value, including type and meaning.
///
/// ## Errors
///
/// - `error.ErrorName`: When this error occurs and why
/// - `error.AnotherError`: When this error occurs
///
/// ## Example
///
/// ```zig
/// const result = try functionName(allocator, input);
/// defer allocator.free(result);
/// ```
pub fn functionName(param1: Type1, param2: Type2) !ReturnType {
    // Implementation
}
```

### Example: ASCII Lowercase

```zig
/// Converts ASCII uppercase letters to lowercase.
///
/// Implements WHATWG Infra "ASCII lowercase" per §4.7.
///
/// Replaces all ASCII upper alphas (U+0041 A to U+005A Z) with their
/// corresponding ASCII lower alpha (U+0061 a to U+007A z). Non-ASCII
/// characters and non-alpha characters are unchanged.
///
/// ## Spec Reference
///
/// https://infra.spec.whatwg.org/#ascii-lowercase
///
/// ## Algorithm (Infra §4.7)
///
/// To ASCII lowercase a string, replace all ASCII upper alphas in the 
/// string with their corresponding code point in ASCII lower alpha.
///
/// ## Parameters
///
/// - `allocator`: Allocator for result string
/// - `string`: Input string (UTF-8 encoded)
///
/// ## Returns
///
/// New string with ASCII uppercase converted to lowercase. Caller owns
/// the returned memory and must free it.
///
/// ## Errors
///
/// - `error.OutOfMemory`: If allocation fails
///
/// ## Example
///
/// ```zig
/// const input = "Hello WORLD";
/// const output = try asciiLowercase(allocator, input);
/// defer allocator.free(output);
/// 
/// // output is "hello world"
/// ```
pub fn asciiLowercase(allocator: Allocator, string: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, string.len);
    errdefer allocator.free(result);
    
    for (string, 0..) |byte, i| {
        if (byte >= 'A' and byte <= 'Z') {
            result[i] = byte + 0x20;
        } else {
            result[i] = byte;
        }
    }
    
    return result;
}
```

---

## Type Documentation

### Structs

```zig
/// [Brief description of what this struct represents].
///
/// [Detailed explanation of purpose, use cases, and relationships to other types]
///
/// ## Spec Reference
///
/// https://infra.spec.whatwg.org/#[type-name]
///
/// ## Fields
///
/// - `field1`: Description of field
/// - `field2`: Description of field
///
/// ## Example
///
/// ```zig
/// const instance = TypeName{ .field1 = value1, .field2 = value2 };
/// ```
pub const TypeName = struct {
    field1: Type1,
    field2: Type2,
};
```

### Example: OrderedMap

```zig
/// Ordered map that preserves insertion order.
///
/// Implements WHATWG Infra "ordered map" per §5.2. Unlike Zig's standard
/// HashMap, this implementation preserves the order in which entries were
/// inserted, as required by the Infra specification.
///
/// ## Spec Reference
///
/// https://infra.spec.whatwg.org/#ordered-map
///
/// ## Implementation
///
/// Uses parallel arrays (keys and values) to maintain insertion order.
/// Lookups are O(n) but iteration is cache-friendly and preserves order.
///
/// ## Fields
///
/// - `keys`: List of keys in insertion order
/// - `values`: List of corresponding values in same order
/// - `allocator`: Allocator used for keys and values
///
/// ## Example
///
/// ```zig
/// var map = OrderedMap([]const u8, u32).init(allocator);
/// defer map.deinit();
/// 
/// try map.set("first", 100);
/// try map.set("second", 200);
/// 
/// // Iteration preserves insertion order
/// var iter = map.iterator();
/// while (iter.next()) |entry| {
///     std.debug.print("{s}: {}\n", .{ entry.key, entry.value });
/// }
/// // Prints:
/// // first: 100
/// // second: 200
/// ```
pub const OrderedMap = struct {
    keys: std.ArrayList(K),
    values: std.ArrayList(V),
    allocator: Allocator,
    
    pub fn init(allocator: Allocator) OrderedMap {
        return .{
            .keys = std.ArrayList(K).init(allocator),
            .values = std.ArrayList(V).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *OrderedMap) void {
        self.keys.deinit();
        self.values.deinit();
    }
};
```

### Enums

```zig
/// [Description of what this enum represents].
///
/// ## Values
///
/// - `variant1`: Description
/// - `variant2`: Description
pub const EnumName = enum {
    variant1,
    variant2,
};
```

### Unions

```zig
/// [Description of what this union represents].
///
/// [Explanation of different variants and when each is used]
///
/// ## Variants
///
/// - `variant1`: Description and when used
/// - `variant2`: Description and when used
pub const UnionName = union(enum) {
    variant1: Type1,
    variant2: Type2,
};
```

### Example: InfraValue

```zig
/// Infra value that can hold any JSON-compatible value.
///
/// Represents the Infra value types from §6. Used when parsing JSON into
/// Infra primitives or serializing Infra primitives to JSON.
///
/// ## Variants
///
/// - `null_value`: Represents JSON null
/// - `boolean`: Represents JSON boolean (true/false)
/// - `number`: Represents JSON number (stored as f64)
/// - `string`: Represents JSON string (UTF-8 bytes)
/// - `list`: Represents JSON array (ordered list of InfraValue)
/// - `map`: Represents JSON object (ordered map of string keys to InfraValue)
///
/// ## Memory Management
///
/// InfraValue owns its data. Call `deinit()` to free all nested allocations:
///
/// ```zig
/// const value = try parseJsonStringToInfraValue(allocator, json);
/// defer value.deinit(allocator); // Recursively frees all data
/// ```
pub const InfraValue = union(enum) {
    null_value: void,
    boolean: bool,
    number: f64,
    string: []const u8,
    list: std.ArrayList(InfraValue),
    map: OrderedMap([]const u8, InfraValue),
    
    /// Recursively frees all memory owned by this value.
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
                for (m.keys.items) |key| {
                    allocator.free(key);
                }
                for (m.values.items) |value| {
                    value.deinit(allocator);
                }
                m.deinit();
            },
            else => {},
        }
    }
};
```

---

## CHANGELOG.md Format

Follow [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) format.

### Structure

```markdown
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- New features

### Changed
- Changes to existing functionality

### Deprecated
- Soon-to-be removed features

### Removed
- Removed features

### Fixed
- Bug fixes

### Security
- Vulnerability fixes

## [1.0.0] - 2024-01-15

### Added
- Initial release
- List operations (§5.1)
- Ordered map operations (§5.2)
```

### Example Entry

```markdown
## [Unreleased]

### Added

- **List Operations (Infra §5.1)** ✅
  - `append()` - Add item to end of list
  - `prepend()` - Add item to beginning of list
  - `remove()` - Remove item at index
  - `contains()` - Check if list contains item
  - Complete spec compliance with WHATWG Infra §5.1
  - Comprehensive test coverage (100%)
  - Performance: O(1) append, O(n) prepend/remove
  - Spec reference: https://infra.spec.whatwg.org/#lists

- **String Operations (Infra §4.7)** ✅
  - `asciiLowercase()` - Convert ASCII uppercase to lowercase
  - `asciiUppercase()` - Convert ASCII lowercase to uppercase
  - `stripNewlines()` - Remove LF and CR characters
  - `stripLeadingAndTrailingWhitespace()` - Remove whitespace
  - Fast path optimization for ASCII-only strings
  - Spec reference: https://infra.spec.whatwg.org/#strings

### Changed

- Improved `OrderedMap.get()` performance for small maps (< 8 entries)
  - Before: Always linear search
  - After: Optimized cache-friendly linear search
  - Benchmark: 2x faster for 4-entry maps

### Fixed

- Fixed memory leak in `parseJsonStringToInfraValue()` when parsing nested objects
  - Issue: Nested maps were not being freed on error
  - Fix: Added `errdefer` cleanup for all nested allocations
  - Test: `test "json parse - no leaks on error with nested objects"`
```

---

## README.md Updates

When adding new features, update README.md to reflect them.

### Features Section

```markdown
## Features

### Lists (§5.1)
- ✅ Append, prepend, remove operations
- ✅ Contains, index-of operations
- ✅ Iteration with `for` loops
- ✅ Stack and queue patterns

### Ordered Maps (§5.2)
- ✅ Set, get, remove operations
- ✅ Preserves insertion order
- ✅ Iteration in insertion order
- ✅ Key existence checking

### Strings (§4.7)
- ✅ ASCII case conversion
- ✅ Whitespace stripping
- ✅ Newline removal
- ✅ Fast paths for ASCII

### JSON (§6)
- ✅ Parse JSON to Infra values
- ✅ Serialize Infra values to JSON
- ✅ Full type support (null, bool, number, string, array, object)

### Base64 (§7)
- ✅ Forgiving base64 decode
- ✅ Forgiving base64 encode
- ✅ Whitespace handling per spec

### Namespaces (§8)
- ✅ HTML, SVG, MathML namespace URIs
- ✅ XML, XLink, XMLNS namespace URIs
```

### Usage Section

```markdown
## Usage

```zig
const std = @import("std");
const infra = @import("infra");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Create a list
    var list = std.ArrayList(u32).init(allocator);
    defer list.deinit();
    
    try list.append(10);
    try list.append(20);
    
    // Create an ordered map
    var map = infra.OrderedMap([]const u8, u32).init(allocator);
    defer map.deinit();
    
    try map.set("first", 100);
    try map.set("second", 200);
    
    // String operations
    const lowercase = try infra.asciiLowercase(allocator, "HELLO");
    defer allocator.free(lowercase);
    
    // JSON parsing
    const json = "{\"key\": \"value\"}";
    const value = try infra.parseJsonStringToInfraValue(allocator, json);
    defer value.deinit(allocator);
}
```
```

---

## Completion Reports

When completing a feature or phase, create a completion report in `summaries/completion/`.

### Template

```markdown
# [Feature/Phase Name] Complete

## Summary

[Brief overview of what was completed]

## What Was Implemented

### [Component 1]
- Feature 1
- Feature 2
- Feature 3

### [Component 2]
- Feature A
- Feature B

## Spec Compliance

- ✅ Infra §X.Y - [Section name]
- ✅ Infra §X.Z - [Section name]
- ✅ All algorithms implemented exactly per spec
- ✅ All edge cases handled

## Test Coverage

- ✅ Happy path tests
- ✅ Edge case tests
- ✅ Error case tests
- ✅ Memory safety tests (no leaks)
- ✅ Spec compliance tests

Total: X tests, 100% passing

## Performance

[Benchmark results if applicable]

## Documentation

- ✅ Inline documentation complete
- ✅ README.md updated
- ✅ CHANGELOG.md updated
- ✅ Examples provided

## Files Changed

- `src/file1.zig` - [What changed]
- `src/file2.zig` - [What changed]
- `tests/unit/file1_test.zig` - [New tests]

## Next Steps

[What should be done next, if applicable]
```

---

## Key Takeaways

1. **Every public item needs documentation** - No exceptions
2. **Reference the Infra spec** - Include section numbers and URLs
3. **Provide examples** - Show how to use the API
4. **Document memory management** - Make cleanup requirements clear
5. **Keep CHANGELOG.md updated** - Document all changes
6. **Update README.md** - Reflect new features
7. **Use primitive names** - Lists, maps, strings (not domain-specific terms)

**Remember**: Documentation is part of the implementation. If it's not documented, it's not done.
