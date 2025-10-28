# Testing Requirements Skill

## When to use this skill

Load this skill when:
- Writing new tests
- Ensuring test coverage
- Verifying memory safety (no leaks)
- Implementing TDD workflows
- Testing Infra spec compliance

## What this skill provides

Testing standards and patterns for Infra implementation:
- Test coverage requirements (happy path, edge cases, errors, memory safety, spec compliance)
- Memory leak testing with `std.testing.allocator`
- Test organization patterns
- TDD workflow
- Refactoring rules (never modify existing tests)

---

## Test Naming Guidelines

Use descriptive names that clearly indicate what primitive operation is being tested.

### Good Test Names

✅ **Clear and specific**:
- `test "list append - adds item to end"`
- `test "ordered map set - updates existing key"`
- `test "ascii lowercase - converts uppercase to lowercase"`
- `test "json parse - handles nested objects"`
- `test "base64 decode - rejects invalid characters"`

### Variable Names in Tests

Use generic names that reflect Infra primitives:
- **Lists**: `list`, `items`, `values`, `elements`
- **Maps**: `map`, `entries`, `key`, `value`
- **Sets**: `set`, `members`, `items`
- **Strings**: `string`, `input`, `output`, `text`
- **Bytes**: `bytes`, `data`, `buffer`

**Example**:
```zig
test "list append - adds item to end" {
    const allocator = std.testing.allocator;
    
    var list = std.ArrayList(u8).init(allocator);
    defer list.deinit();
    
    try list.append(42);
    
    try std.testing.expectEqual(@as(usize, 1), list.items.len);
    try std.testing.expectEqual(@as(u8, 42), list.items[0]);
}
```

---

## Test Location Rules

**NEVER write tests inside `src/` files!**

- **Unit tests**: Separate files in `tests/unit/` directory
  - One test file per source file (e.g., `src/list.zig` → `tests/unit/list_test.zig`)
  - Import the module under test: `const list = @import("infra").list;`
  - Use `std.testing.allocator` for memory leak detection

- **Integration tests**: In `tests/` root for cross-module tests
  - Test interactions between primitives (e.g., JSON → Infra values)

**Rationale**: Separate test files keep source code clean, enable faster compilation (tests only compiled when needed), and follow Zig best practices.

---

## Test Coverage Requirements

### 1. Happy Path - Normal Usage

Test the common, expected use case.

```zig
test "list append - adds item successfully" {
    const allocator = std.testing.allocator;
    
    var list = std.ArrayList(u32).init(allocator);
    defer list.deinit();
    
    try list.append(10);
    try list.append(20);
    
    try std.testing.expectEqual(@as(usize, 2), list.items.len);
    try std.testing.expectEqual(@as(u32, 10), list.items[0]);
    try std.testing.expectEqual(@as(u32, 20), list.items[1]);
}
```

### 2. Edge Cases - Boundary Conditions

Test empty inputs, single items, large inputs, etc.

```zig
test "list append - empty list" {
    const allocator = std.testing.allocator;
    
    var list = std.ArrayList(u32).init(allocator);
    defer list.deinit();
    
    try std.testing.expectEqual(@as(usize, 0), list.items.len);
}

test "ordered map get - nonexistent key returns null" {
    const allocator = std.testing.allocator;
    
    var map = OrderedMap([]const u8, u32).init(allocator);
    defer map.deinit();
    
    const result = map.get("nonexistent");
    try std.testing.expectEqual(@as(?u32, null), result);
}

test "string strip newlines - string with no newlines" {
    const allocator = std.testing.allocator;
    
    const input = "hello world";
    const output = try stripNewlines(allocator, input);
    defer allocator.free(output);
    
    try std.testing.expectEqualStrings(input, output);
}
```

### 3. Error Cases - Invalid Inputs

Test that functions properly reject invalid input.

```zig
test "base64 decode - rejects invalid characters" {
    const allocator = std.testing.allocator;
    
    const invalid = "abc$def"; // '$' is not valid base64
    
    try std.testing.expectError(
        error.InvalidBase64,
        forgivingBase64Decode(allocator, invalid)
    );
}

test "json parse - rejects malformed JSON" {
    const allocator = std.testing.allocator;
    
    const malformed = "{\"key\": }"; // Missing value
    
    try std.testing.expectError(
        error.InvalidJson,
        parseJsonStringToInfraValue(allocator, malformed)
    );
}

test "list remove - out of bounds index fails" {
    const allocator = std.testing.allocator;
    
    var list = std.ArrayList(u32).init(allocator);
    defer list.deinit();
    
    try list.append(10);
    
    // Accessing index 1 when only index 0 exists
    // Note: orderedRemove returns the removed item, not an error
    // But accessing out of bounds is undefined behavior
    // Test that we handle bounds correctly in our wrapper
}
```

### 4. Memory Safety - No Leaks

**CRITICAL**: Always use `std.testing.allocator` to detect leaks.

```zig
test "ordered map - no memory leaks" {
    const allocator = std.testing.allocator; // Detects leaks!
    
    var map = OrderedMap([]const u8, u32).init(allocator);
    defer map.deinit();
    
    try map.set("key1", 100);
    try map.set("key2", 200);
    
    // Test passes only if all allocations are freed by deinit()
}

test "json parse - no leaks on error" {
    const allocator = std.testing.allocator;
    
    const malformed = "{invalid}";
    
    _ = parseJsonStringToInfraValue(allocator, malformed) catch |err| {
        try std.testing.expectEqual(error.InvalidJson, err);
        // Even on error, no allocations should be leaked
    };
    
    // Test passes only if no leaks
}
```

### 5. Spec Compliance - Matches WHATWG Infra Behavior

Test that implementation follows the spec algorithm exactly.

```zig
test "list append - follows Infra §5.1 algorithm" {
    // Reference: https://infra.spec.whatwg.org/#list-append
    // "To append to a list is to add the given item to the end of the list."
    
    const allocator = std.testing.allocator;
    
    var list = std.ArrayList(u32).init(allocator);
    defer list.deinit();
    
    // Initial state: empty list
    try std.testing.expectEqual(@as(usize, 0), list.items.len);
    
    // After append: item is at the end
    try list.append(10);
    try std.testing.expectEqual(@as(usize, 1), list.items.len);
    try std.testing.expectEqual(@as(u32, 10), list.items[0]);
    
    // After second append: new item is at the end
    try list.append(20);
    try std.testing.expectEqual(@as(usize, 2), list.items.len);
    try std.testing.expectEqual(@as(u32, 10), list.items[0]);
    try std.testing.expectEqual(@as(u32, 20), list.items[1]);
}

test "ordered map set - follows Infra §5.2 algorithm" {
    // Reference: https://infra.spec.whatwg.org/#map-set
    // "To set the value of an entry in an ordered map to a given value is to 
    // update the value of any existing entry if the map contains an entry 
    // with the given key, or if none such exists, to add a new entry with 
    // the given key/value to the end of the map."
    
    const allocator = std.testing.allocator;
    
    var map = OrderedMap([]const u8, u32).init(allocator);
    defer map.deinit();
    
    // Case 1: New key - adds to end
    try map.set("key1", 100);
    try std.testing.expectEqual(@as(?u32, 100), map.get("key1"));
    
    // Case 2: Existing key - updates value (preserves order)
    try map.set("key1", 200);
    try std.testing.expectEqual(@as(?u32, 200), map.get("key1"));
    
    // Case 3: Another new key - adds to end (after key1)
    try map.set("key2", 300);
    
    // Verify insertion order preserved
    var iter = map.iterator();
    const entry1 = iter.next().?;
    try std.testing.expectEqualStrings("key1", entry1.key);
    try std.testing.expectEqual(@as(u32, 200), entry1.value);
    
    const entry2 = iter.next().?;
    try std.testing.expectEqualStrings("key2", entry2.key);
    try std.testing.expectEqual(@as(u32, 300), entry2.value);
}
```

---

## Memory Leak Testing

**CRITICAL: Always use `std.testing.allocator`**

The testing allocator tracks all allocations and will fail the test if any memory is leaked.

### Pattern: defer cleanup

```zig
test "proper cleanup with defer" {
    const allocator = std.testing.allocator;
    
    var list = std.ArrayList(u8).init(allocator);
    defer list.deinit(); // ✅ ALWAYS defer cleanup
    
    try list.append(42);
    
    // list.deinit() is called automatically when test ends
    // If we forgot 'defer', test would fail with memory leak
}
```

### Pattern: errdefer for error paths

```zig
test "cleanup on error with errdefer" {
    const allocator = std.testing.allocator;
    
    var list = std.ArrayList(u8).init(allocator);
    defer list.deinit();
    
    var map = OrderedMap([]const u8, u32).init(allocator);
    defer map.deinit();
    
    // If this fails, both defer statements run
    try map.set("key", 100);
    
    // If we reach here, both structures will be cleaned up
}
```

### Pattern: Complex cleanup

```zig
test "complex cleanup - InfraValue with nested data" {
    const allocator = std.testing.allocator;
    
    const json = "{\"key\": [1, 2, 3]}";
    const value = try parseJsonStringToInfraValue(allocator, json);
    defer value.deinit(allocator); // Recursively frees all nested data
    
    // value.deinit() handles:
    // - Freeing the "key" string
    // - Freeing the array list
    // - Freeing the map
    // All automatically!
}
```

---

## Test Organization

### One test per behavior

```zig
// ✅ GOOD: One test per behavior
test "list append - adds to end" { }
test "list prepend - adds to beginning" { }
test "list remove - removes at index" { }

// ❌ BAD: Multiple behaviors in one test
test "list operations" {
    // Tests append, prepend, remove all in one
    // Hard to debug when it fails
}
```

### Group related tests with descriptive names

```zig
// Infra lists (§5.1)
test "list append - adds to end" { }
test "list prepend - adds to beginning" { }
test "list remove - removes at index" { }
test "list contains - finds existing item" { }

// Infra ordered maps (§5.2)
test "ordered map set - adds new entry" { }
test "ordered map set - updates existing entry" { }
test "ordered map get - returns value for existing key" { }
test "ordered map get - returns null for nonexistent key" { }
test "ordered map remove - removes entry" { }
```

---

## TDD Workflow

### Test-Driven Development for Infra

1. **Read the spec algorithm completely**
   - Open https://infra.spec.whatwg.org/
   - Read entire algorithm (all steps)
   - Understand preconditions and postconditions

2. **Write a failing test**
   ```zig
   test "ascii lowercase - converts uppercase" {
       const allocator = std.testing.allocator;
       
       const input = "HELLO";
       const output = try asciiLowercase(allocator, input);
       defer allocator.free(output);
       
       try std.testing.expectEqualStrings("hello", output);
   }
   ```
   
   Run: `zig build test`
   
   Expected: Compilation error (function doesn't exist yet)

3. **Write minimum code to compile**
   ```zig
   pub fn asciiLowercase(allocator: Allocator, string: []const u8) ![]u8 {
       _ = allocator;
       _ = string;
       return error.NotImplemented;
   }
   ```
   
   Run: `zig build test`
   
   Expected: Test fails (returns error, not "hello")

4. **Implement the algorithm**
   ```zig
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
   
   Run: `zig build test`
   
   Expected: Test passes!

5. **Add more tests for edge cases**
   ```zig
   test "ascii lowercase - preserves lowercase" { }
   test "ascii lowercase - preserves non-alpha" { }
   test "ascii lowercase - handles empty string" { }
   test "ascii lowercase - handles unicode (non-ASCII)" { }
   ```

6. **Refactor if needed**
   - Improve performance
   - Simplify code
   - **Never modify existing tests** (they are the contract!)

---

## Refactoring Rules

### Never Modify Existing Tests

**Existing tests define the contract. Never change them during refactoring.**

```zig
// Existing test (DO NOT MODIFY)
test "list append - adds to end" {
    const allocator = std.testing.allocator;
    
    var list = std.ArrayList(u32).init(allocator);
    defer list.deinit();
    
    try list.append(10);
    
    try std.testing.expectEqual(@as(usize, 1), list.items.len);
    try std.testing.expectEqual(@as(u32, 10), list.items[0]);
}

// ✅ GOOD: Add NEW tests for additional cases
test "list append - handles multiple appends" { }
test "list append - works with empty list" { }

// ❌ BAD: Modifying existing test expectations
// This breaks the contract!
```

### When to Add New Tests

Add new tests when:
- ✅ Discovering a bug (add failing test first, then fix)
- ✅ Adding new functionality (write test first)
- ✅ Clarifying existing behavior (add test for unclear case)

Do NOT add tests when:
- ❌ Existing test already covers the case
- ❌ Test would duplicate existing coverage

---

## Test Documentation

### Spec References in Tests

Link to the spec section being tested:

```zig
/// Tests Infra "strip newlines" algorithm (§4.7).
/// Reference: https://infra.spec.whatwg.org/#strip-newlines
test "strip newlines - removes LF and CR" {
    // Test implementation...
}
```

### Complex Algorithm Tests

For complex algorithms, comment each spec step:

```zig
test "forgiving base64 decode - follows §7 algorithm" {
    // Reference: https://infra.spec.whatwg.org/#forgiving-base64-decode
    
    const allocator = std.testing.allocator;
    const input = "SGVs bG8="; // "Hello" with spaces
    
    // Step 1: Remove ASCII whitespace
    // Expected: "SGVsbG8="
    
    // Step 2: Remove trailing '=' characters
    // Expected: "SGVsbG8"
    
    // Step 3-4: Validate character set
    // Expected: All characters are valid base64
    
    // Step 5: Decode
    const output = try forgivingBase64Decode(allocator, input);
    defer allocator.free(output);
    
    try std.testing.expectEqualStrings("Hello", output);
}
```

---

## Common Testing Patterns

### Testing String Operations

```zig
test "string operation - basic case" {
    const allocator = std.testing.allocator;
    
    const input = "input string";
    const output = try operation(allocator, input);
    defer allocator.free(output); // Always free allocated strings
    
    try std.testing.expectEqualStrings("expected", output);
}
```

### Testing Collections

```zig
test "collection operation - verify state" {
    const allocator = std.testing.allocator;
    
    var collection = Collection.init(allocator);
    defer collection.deinit();
    
    // Perform operation
    try collection.add(item);
    
    // Verify state
    try std.testing.expectEqual(expected_size, collection.size());
    try std.testing.expect(collection.contains(item));
}
```

### Testing Error Conditions

```zig
test "operation - rejects invalid input" {
    const allocator = std.testing.allocator;
    
    try std.testing.expectError(
        error.InvalidInput,
        operation(allocator, invalid_input)
    );
}
```

---

## Integration with Other Skills

This skill coordinates with:
- **whatwg_compliance** - Test spec algorithm compliance
- **zig_standards** - Follow Zig testing conventions
- **performance_optimization** - Performance tests to catch regressions

Load all relevant skills for complete testing guidance.

---

## Key Takeaways

1. **Always use std.testing.allocator** - Catches memory leaks
2. **defer cleanup** - Ensures proper cleanup
3. **One test per behavior** - Easy debugging
4. **Test all 5 categories** - Happy path, edge cases, errors, memory, spec
5. **TDD workflow** - Write test first, implement second
6. **Never modify existing tests** - They are the contract
7. **Reference the spec** - Link to Infra spec sections

**Remember**: Tests are the specification in code. If tests pass, implementation is correct.
