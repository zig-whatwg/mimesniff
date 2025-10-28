# Zig Programming Standards Skill

## When to use this skill

Load this skill automatically when:
- Writing or refactoring Zig code
- Implementing Infra algorithms in Zig
- Designing struct layouts and type systems
- Managing memory with allocators
- Handling errors in Infra operations
- Writing idiomatic Zig code

## What this skill provides

Zig-specific programming patterns and idioms for Infra implementation:
- Naming conventions and code style
- Error handling patterns (Infra errors → Zig error unions)
- Memory management patterns (allocator, arena, defer)
- Type safety best practices
- Comptime programming for zero-cost abstractions

---

## Naming Conventions

```zig
// Types: PascalCase
pub const OrderedMap = struct { ... };
pub const InfraValue = union(enum) { ... };
pub const InfraError = error { ... };

// Functions and variables: snake_case
pub fn asciiLowercase(allocator: Allocator, string: []const u8) ![]u8 { ... }
pub fn parseJsonString(allocator: Allocator, json: []const u8) !InfraValue { ... }
const my_variable: i32 = 42;
const item_count: usize = 0;

// Constants: SCREAMING_SNAKE_CASE
pub const MAX_STRING_LENGTH: usize = 1_000_000;
pub const HTML_NAMESPACE: []const u8 = "http://www.w3.org/1999/xhtml";
pub const SVG_NAMESPACE: []const u8 = "http://www.w3.org/2000/svg";

// Private members: prefix with underscore when needed for clarity
const _internal_buffer: [256]u8 = undefined;
fn _validateInput() bool { ... }
```

---

## Error Handling

### Domain-Specific Error Sets

```zig
// Define error sets matching Infra operations
pub const InfraError = error{
    // Parsing errors
    InvalidJson,
    InvalidBase64,
    InvalidCodePoint,
    InvalidUtf8,
    
    // Algorithm errors
    IndexOutOfBounds,
    KeyNotFound,
    InvalidInput,
    EmptyList,
    
    // String errors
    InvalidCharacter,
    StringTooLong,
};

// Combine with Allocator.Error for operations that allocate
pub fn parseJsonStringToInfraValue(
    allocator: Allocator,
    json: []const u8,
) (Allocator.Error || InfraError)!InfraValue {
    // May fail with OutOfMemory OR InvalidJson
}
```

### Error Union Patterns

```zig
// ✅ GOOD: Use error unions for operations that can fail
pub fn orderedMapGet(map: OrderedMap, key: []const u8) !Value {
    return map.getOrError(key) catch error.KeyNotFound;
}

// ✅ GOOD: Use optionals for "not found" semantics
pub fn orderedMapGet(map: OrderedMap, key: []const u8) ?Value {
    return map.get(key); // Returns null if key not found
}

// ❌ BAD: Sentinel values (like -1) lose type information
pub fn findIndex(list: []const u8, item: u8) isize {
    // Returns -1 if not found - fragile!
}

// Provide context in error handling
const value = parseJsonString(allocator, json) catch |err| switch (err) {
    error.InvalidJson => {
        std.log.err("Invalid JSON: {s}", .{json});
        return err;
    },
    error.OutOfMemory => {
        std.log.err("Out of memory parsing JSON", .{});
        return err;
    },
    else => return err,
};
```

### defer for Cleanup

```zig
// ✅ GOOD: defer ensures cleanup even on error
pub fn processString(allocator: Allocator, input: []const u8) ![]u8 {
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit(); // Runs even if error occurs
    
    try buffer.appendSlice(input);
    const result = try stripNewlines(allocator, buffer.items);
    
    return result; // buffer cleaned up automatically
}

// errdefer for cleanup only on error
pub fn createOrderedMap(allocator: Allocator) !OrderedMap {
    var map = OrderedMap.init(allocator);
    errdefer map.deinit(); // Only runs if we return error after this point
    
    try map.set("default", 0);
    
    return map; // Success - errdefer does NOT run
}
```

---

## Memory Management

### Allocator Pattern

```zig
// All functions that allocate take an Allocator
pub fn operation(allocator: Allocator, input: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, input.len);
    errdefer allocator.free(result);
    
    // Process...
    
    return result; // Caller owns and must free
}

// Caller pattern
const result = try operation(allocator, input);
defer allocator.free(result); // Caller frees
```

### defer Pattern

```zig
// ✅ GOOD: defer immediately after allocation
pub fn example(allocator: Allocator) !void {
    var list = std.ArrayList(u8).init(allocator);
    defer list.deinit(); // Declare cleanup immediately
    
    try list.append(42);
    
    // List automatically cleaned up when function exits
}

// ❌ BAD: Forgetting defer causes memory leaks
pub fn example(allocator: Allocator) !void {
    var list = std.ArrayList(u8).init(allocator);
    try list.append(42);
    // Memory leak! list.deinit() never called
}
```

### Arena Allocator Pattern

```zig
// For temporary allocations in algorithms
pub fn complexAlgorithm(allocator: Allocator, input: []const u8) !Result {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit(); // Free everything at once
    
    const temp_allocator = arena.allocator();
    
    // All temporary allocations use temp_allocator
    const temp_list = std.ArrayList(u8).init(temp_allocator);
    const temp_buffer = try temp_allocator.alloc(u8, 1024);
    
    // Process...
    
    // Final result uses original allocator (outlives arena)
    const result = try allocator.dupe(Result, computed_result);
    
    return result; // All temp allocations freed by arena.deinit()
}
```

---

## Type Safety

### Const Correctness

```zig
// Use const for immutable data
pub fn processString(string: []const u8) usize {
    // string cannot be modified (const)
    return string.len;
}

// Mutable only when necessary
pub fn modifyList(list: *std.ArrayList(u8)) !void {
    // list can be modified (mutable pointer)
    try list.append(42);
}
```

### Explicit Types

```zig
// ✅ GOOD: Explicit integer types prevent overflow
const count: usize = list.items.len;
const byte: u8 = data[index];
const code_point: u21 = 0x1F600;

// ❌ BAD: Implicit integer literals can cause issues
const count = list.items.len; // Type inferred, may be wrong
```

### Tagged Unions

```zig
// ✅ GOOD: Tagged unions for sum types
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
                for (l.items) |item| item.deinit(allocator);
                l.deinit();
            },
            .map => |*m| m.deinit(),
            else => {},
        }
    }
};
```

---

## Struct Patterns

### Init/Deinit Pattern

```zig
pub const OrderedMap = struct {
    keys: std.ArrayList(K),
    values: std.ArrayList(V),
    allocator: Allocator,
    
    // init: creates new instance
    pub fn init(allocator: Allocator) OrderedMap {
        return .{
            .keys = std.ArrayList(K).init(allocator),
            .values = std.ArrayList(V).init(allocator),
            .allocator = allocator,
        };
    }
    
    // deinit: frees all resources
    pub fn deinit(self: *OrderedMap) void {
        self.keys.deinit();
        self.values.deinit();
    }
    
    // Methods
    pub fn set(self: *OrderedMap, key: K, value: V) !void {
        // Check if key exists
        if (self.getIndex(key)) |index| {
            self.values.items[index] = value;
            return;
        }
        
        // Add new entry
        try self.keys.append(key);
        try self.values.append(value);
    }
};
```

### Method Conventions

```zig
// self: immutable reference (read-only)
pub fn get(self: OrderedMap, key: K) ?V { }

// self: mutable pointer (can modify)
pub fn set(self: *OrderedMap, key: K, value: V) !void { }

// Functions that don't need self are free functions
pub fn merge(allocator: Allocator, map1: OrderedMap, map2: OrderedMap) !OrderedMap { }
```

---

## Comptime Programming

### Generic Functions

```zig
// Generic function using comptime
pub fn append(comptime T: type, list: *std.ArrayList(T), item: T) !void {
    try list.append(item);
}

// Generic OrderedMap
pub fn OrderedMap(comptime K: type, comptime V: type) type {
    return struct {
        keys: std.ArrayList(K),
        values: std.ArrayList(V),
        allocator: Allocator,
        
        const Self = @This();
        
        pub fn init(allocator: Allocator) Self {
            return .{
                .keys = std.ArrayList(K).init(allocator),
                .values = std.ArrayList(V).init(allocator),
                .allocator = allocator,
            };
        }
        
        pub fn deinit(self: *Self) void {
            self.keys.deinit();
            self.values.deinit();
        }
    };
}
```

### Compile-Time Constants

```zig
// Namespace URIs as comptime constants
pub const Namespaces = struct {
    pub const HTML = "http://www.w3.org/1999/xhtml";
    pub const SVG = "http://www.w3.org/2000/svg";
    pub const MATHML = "http://www.w3.org/1998/Math/MathML";
    pub const XLINK = "http://www.w3.org/1999/xlink";
    pub const XML = "http://www.w3.org/XML/1998/namespace";
    pub const XMLNS = "http://www.w3.org/2000/xmlns/";
};

// Comptime validation
pub fn validateNamespace(comptime namespace: []const u8) void {
    comptime {
        if (namespace.len == 0) {
            @compileError("Namespace cannot be empty");
        }
    }
}
```

---

## Testing Patterns

### Test Block Structure

```zig
test "function - behavior description" {
    // Arrange
    const allocator = std.testing.allocator;
    var list = std.ArrayList(u8).init(allocator);
    defer list.deinit();
    
    // Act
    try list.append(42);
    
    // Assert
    try std.testing.expectEqual(@as(usize, 1), list.items.len);
    try std.testing.expectEqual(@as(u8, 42), list.items[0]);
}
```

### Common Assertions

```zig
// Equality
try std.testing.expectEqual(expected, actual);

// Strings
try std.testing.expectEqualStrings("expected", actual);

// Slices
try std.testing.expectEqualSlices(u8, expected, actual);

// Optionals
try std.testing.expect(optional == null);
try std.testing.expect(optional != null);

// Errors
try std.testing.expectError(error.InvalidInput, operation());

// Boolean
try std.testing.expect(condition);
```

---

## Performance Patterns

### Inline Functions

```zig
// Inline small, frequently called functions
pub inline fn isAscii(byte: u8) bool {
    return byte < 0x80;
}

pub inline fn isWhitespace(byte: u8) bool {
    return byte == ' ' or byte == '\t' or byte == '\n' or byte == '\r';
}

// Don't inline large functions
pub fn complexOperation(input: []const u8) ![]u8 {
    // Large function - let compiler decide
}
```

### Preallocate When Size Known

```zig
// ✅ GOOD: Preallocate capacity
pub fn processItems(allocator: Allocator, items: []Item) ![]Result {
    var results = try std.ArrayList(Result).initCapacity(allocator, items.len);
    errdefer results.deinit();
    
    for (items) |item| {
        results.appendAssumeCapacity(processItem(item)); // No reallocation!
    }
    
    return results.toOwnedSlice();
}

// ❌ BAD: Let ArrayList grow incrementally
pub fn processItems(allocator: Allocator, items: []Item) ![]Result {
    var results = std.ArrayList(Result).init(allocator);
    // Will reallocate multiple times
    
    for (items) |item| {
        try results.append(processItem(item));
    }
    
    return results.toOwnedSlice();
}
```

---

## Code Organization

### Module Structure

```zig
//! Module documentation at the top

const std = @import("std");
const Allocator = std.mem.Allocator;

// Public types
pub const TypeName = struct { ... };

// Public constants
pub const CONSTANT = value;

// Public functions
pub fn publicFunction() void { ... }

// Private functions
fn privateFunction() void { ... }

// Tests at the bottom
test "description" { ... }
```

### Import Conventions

```zig
// Standard library
const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

// Local modules
const list = @import("list.zig");
const map = @import("map.zig");
const string = @import("string.zig");
```

---

## Common Idioms

### Optional Unwrapping

```zig
// orelse for default values
const value = optional orelse default_value;

// orelse with early return
const value = optional orelse return error.NotFound;

// if with unwrap
if (optional) |value| {
    // Use value
} else {
    // Handle null
}
```

### For Loops

```zig
// Iterate over slice
for (slice) |item| {
    // Process item
}

// Iterate with index
for (slice, 0..) |item, i| {
    // Use item and index
}

// While loop for manual iteration
var i: usize = 0;
while (i < slice.len) : (i += 1) {
    // Use slice[i]
}
```

### Switch Expressions

```zig
const result = switch (value) {
    .variant1 => 10,
    .variant2 => 20,
    .variant3 => 30,
};

// With capture
const string = switch (infra_value) {
    .string => |s| s,
    else => return error.NotAString,
};
```

---

## Integration with Other Skills

This skill coordinates with:
- **whatwg_compliance** - Implementing Infra algorithms in Zig
- **testing_requirements** - Writing idiomatic Zig tests
- **performance_optimization** - Using Zig features for performance

Load all relevant skills for complete Zig guidance.

---

## Key Takeaways

1. **Naming**: PascalCase types, snake_case functions, SCREAMING_SNAKE_CASE constants
2. **Errors**: Use error unions, provide context, defer cleanup
3. **Memory**: Allocator parameter, defer immediately, use arena for temps
4. **Types**: Const correctness, explicit types, tagged unions
5. **Comptime**: Generics, compile-time validation, zero-cost abstractions
6. **Testing**: std.testing.allocator, arrange-act-assert, descriptive names

**Remember**: Zig emphasizes explicitness and safety. Make memory management and error handling visible in the code.
