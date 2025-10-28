We track work in Beads instead of Markdown. Run \`bd quickstart\` to see how.

# Agent Guidelines for WHATWG Infra Implementation in Zig

## ⚠️ CRITICAL: Ask Clarifying Questions When Unclear

**ALWAYS ask clarifying questions when requirements are ambiguous or unclear.**

### Question-Asking Protocol

When you receive a request that is:
- Ambiguous or has multiple interpretations
- Missing key details needed for implementation
- Unclear about expected behavior or scope
- Could be understood in different ways

**YOU MUST**:
1. ✅ **Ask ONE clarifying question at a time**
2. ✅ **Wait for the answer before proceeding**
3. ✅ **Continue asking questions until you have complete understanding**
4. ✅ **Never make assumptions when you can ask**

### Examples of When to Ask

❓ **Ambiguous request**: "Implement ordered map"
- **Ask**: "Should the ordered map preserve insertion order like JavaScript Map, or maintain sorted order by keys?"

❓ **Missing details**: "Add JSON parsing"
- **Ask**: "Should JSON parsing return Infra values (lists, maps, strings), or JavaScript-compatible values?"

❓ **Unclear scope**: "Optimize list operations"
- **Ask**: "Which operations should be prioritized? Append, prepend, remove, or iteration?"

❓ **Multiple interpretations**: "Handle Unicode in strings"
- **Ask**: "Should strings store UTF-8 bytes ([]const u8), or should we validate and normalize to NFC form?"

### What NOT to Do

❌ **Don't make assumptions and implement something that might be wrong**
❌ **Don't ask multiple questions in one message** (ask one, wait for answer, then ask next)
❌ **Don't proceed with unclear requirements** hoping you guessed correctly
❌ **Don't over-explain options** in the question (keep questions concise)

### Good Question Pattern

```
"I want to make sure I understand correctly: [restate what you think they mean].

Is that correct, or did you mean [alternative interpretation]?"
```

**Remember**: It's better to ask and get it right than to implement the wrong thing quickly.

---

## ⚠️ CRITICAL: Pure Primitives - No Domain-Specific Types

**THIS IS A PRIMITIVE SPECIFICATION LIBRARY** implementing WHATWG Infra for use by OTHER specifications.

### What Infra IS

The WHATWG Infra Standard defines **fundamental building blocks** used by web specifications:

1. **Algorithms** - Declaration patterns, control flow, assertions
2. **Primitive Types** - Nulls, booleans, numbers, bytes, strings, code points
3. **Data Structures** - Lists, ordered maps, ordered sets, stacks, queues, structs, tuples
4. **JSON** - Parsing/serialization between JSON and Infra values
5. **Base64** - Forgiving encoding/decoding
6. **Namespaces** - HTML, MathML, SVG, XLink, XML, XMLNS namespace URI constants

### What Infra is NOT

❌ **NOT a DOM library** - No nodes, elements, documents
❌ **NOT HTML-specific** - No HTML semantics or parsing
❌ **NOT browser APIs** - No Web APIs, just primitives
❌ **NOT domain-specific** - Pure primitives for ANY spec to use

### Scope

✅ **ONLY implement**: Strings, bytes, lists, maps, sets, algorithms, JSON, base64
✅ **Keep it generic**: These primitives are used by DOM, Fetch, URL, etc.
✅ **Pure primitives**: No domain-specific types or behaviors

### Test Guidelines

- Use generic variable names: `list`, `map`, `string`, `bytes`, `value`
- Test primitive operations: append, remove, sort, parse, encode
- No domain-specific test data (no HTML, no URLs, no DOM concepts)

**Example Test**:
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

This project uses **Agent Skills** for specialized knowledge areas. Skills are automatically loaded when relevant to your task.

## Memory Management for Primitives

Infra types use standard Zig allocation patterns - no special reference counting or factory patterns needed.

### Standard Allocation Pattern

```zig
// Lists use ArrayList
var list = std.ArrayList(u8).init(allocator);
defer list.deinit();

try list.append(42);

// Maps use custom OrderedMap (preserves insertion order)
var map = OrderedMap([]const u8, u32).init(allocator);
defer map.deinit();

try map.set("key", 100);

// Strings are just slices
const string: []const u8 = "hello";
```

### Arena Allocation for Temporary Work

```zig
// For algorithms that build intermediate data structures
var arena = std.heap.ArenaAllocator.init(allocator);
defer arena.deinit();
const temp_allocator = arena.allocator();

// Build temporary structures
const temp_list = std.ArrayList(u8).init(temp_allocator);
const result = try processData(temp_allocator, input);

// Everything freed at once when arena.deinit() is called
```

### Memory Safety

- **Always use `defer`** for cleanup
- **Always test with `std.testing.allocator`** to detect leaks
- **No reference counting** - primitives are values, not objects
- **No global state** - everything takes an allocator

---

## Available Skills

Claude automatically loads skills when relevant to your task. You don't need to manually select them.

### 1. **whatwg_compliance** - Specification Compliance

**Automatically loaded when:**
- Implementing Infra algorithms or data structures
- Understanding Infra type definitions
- Checking spec compliance
- Mapping Infra types to Zig

**Provides:**
- Complete WHATWG Infra specification
- Infra → Zig type mappings
- Algorithm implementation patterns
- Spec reference format

**Location:** `skills/whatwg_compliance/`

### 2. **zig_standards** - Zig Programming Patterns

**Automatically loaded when:**
- Writing or refactoring Zig code
- Implementing algorithms
- Managing memory with allocators
- Handling errors

**Provides:**
- Naming conventions and code style
- Error handling patterns
- Memory management patterns (allocator, arena, defer)
- Type safety best practices
- Comptime programming patterns

**Location:** `skills/zig_standards/`

### 3. **testing_requirements** - Test Standards

**Automatically loaded when:**
- Writing tests
- Ensuring test coverage
- Verifying memory safety (no leaks)
- Implementing TDD workflows

**Provides:**
- Test coverage requirements (happy path, edge cases, errors, memory)
- Memory leak testing with `std.testing.allocator`
- Test organization patterns
- TDD workflow

**Location:** `skills/testing_requirements/`

### 4. **performance_optimization** - Primitive Performance

**Automatically loaded when:**
- Optimizing list/map/string operations
- Working on hot paths
- Minimizing allocations

**Provides:**
- Fast paths for common cases (ASCII, small sizes)
- Allocation minimization patterns
- Cache-friendly data structures
- String operation optimization
- JSON parsing optimization
- Base64 encoding optimization

**Location:** `skills/performance_optimization/`

### 5. **documentation_standards** - Documentation Format

**Automatically loaded when:**
- Writing inline documentation
- Updating README.md or CHANGELOG.md
- Documenting design decisions
- Creating completion reports

**Provides:**
- Comprehensive module-level documentation format (`//!`)
- Function and type documentation patterns (`///`)
- Infra spec reference format
- Complete usage examples and common patterns
- README.md update workflow
- CHANGELOG.md format (Keep a Changelog 1.1.0)

**Location:** `skills/documentation_standards/`

### 6. **communication_protocol** - Clarifying Questions ⭐

**ALWAYS ACTIVE** - Applies to every interaction and task.

**Core Principle:**
When requirements are ambiguous, unclear, or could be interpreted multiple ways, **ALWAYS ask clarifying questions** before proceeding.

**Provides:**
- Question-asking protocol (one question at a time)
- When to ask vs. when to proceed
- Question patterns and examples
- Anti-patterns to avoid (assuming, option overload, paralysis)
- Decision tree for "should I ask?"

**Critical Rule:** Ask ONE clarifying question at a time. Wait for answer. Repeat until understanding is complete.

**Location:** `skills/communication_protocol/`

### 7. **browser_benchmarking** - Browser Implementation Research

**Automatically loaded when:**
- Making performance optimization decisions
- Designing collection data structures (List, OrderedMap, OrderedSet)
- Determining inline storage capacity
- Evaluating long-lived page requirements

**Provides:**
- Browser engine implementation analysis (Chromium, Firefox, WebKit)
- Inline storage research and hit rates (70-80%)
- Why 4-element inline storage is optimal
- Comparison: browser C++ vs. Zig tradeoffs
- Recommendations for Zig WHATWG Infra context
- Comptime configuration patterns

**Key Findings:**
- Chromium/Firefox both use 4-element inline storage for vectors
- Chromium uses 10-element preallocation for DOM attributes specifically
- Recommendation: 4-element inline for all Infra collections (generic primitives)

**Location:** `skills/browser_benchmarking/`

### 8. **code_quality_checklist** - Pre-Commit Requirements ⭐

**ALWAYS ACTIVE** - MANDATORY before every git commit.

**Core Principle:**
NEVER commit code without completing ALL quality checks. No exceptions.

**Provides:**
- Pre-commit checklist (formatting, tests, build, review)
- `zig fmt` enforcement (ALWAYS run before commit)
- Test verification requirements
- Git diff review process
- Commit message standards
- Common mistakes to avoid

**Critical Rules:**
1. ✅ **ALWAYS run `zig fmt` before committing**
2. ✅ **ALWAYS run `zig build test` and verify all pass**
3. ✅ **ALWAYS review `git diff --staged` before committing**
4. ✅ **ALWAYS write meaningful commit messages**
5. ✅ **NEVER commit debug code, TODOs, or secrets**

**Zero Tolerance:** Unformatted code, failing tests, or code that doesn't compile.

**Location:** `skills/code_quality_checklist/`

---

## Golden Rules

These apply to ALL work on this project:

### 0. **Ask When Unclear** ⭐
When requirements are ambiguous or unclear, **ASK CLARIFYING QUESTIONS** before proceeding. One question at a time. Wait for answer. Never assume.

### 1. **Complete Spec Understanding**
Read FULL Infra specification from `skills/whatwg_compliance/`, not grep fragments. Every algorithm has context and edge cases.

### 2. **Algorithm Precision**
Infra algorithms are building blocks for other specs. Implement EXACTLY as specified, step by step. Even small deviations can break dependent specs.

### 3. **Memory Safety**
Zero leaks, proper cleanup with defer, test with `std.testing.allocator`. No exceptions.

### 4. **Test First**
Write tests before implementation. Infra primitives are highly testable in isolation.

### 5. **Zero Dependencies**
Infra should not depend on domain-specific types. Keep it pure primitives. This is what makes Infra reusable.

### 6. **Performance Matters** (but spec compliance comes first)
Infra is used heavily by other specs. Optimize for speed and low allocation. But never sacrifice correctness for speed.

---

## Critical Project Context

### What Makes Infra Special

1. **Foundation Layer** - DOM, Fetch, URL all depend on Infra
2. **No Domain Logic** - Pure primitives only
3. **Spec Compliance Critical** - Other specs assume Infra matches WHATWG exactly
4. **Used Everywhere** - Performance matters

### Code Quality

- Production-ready codebase
- Zero tolerance for memory leaks
- Zero tolerance for breaking changes without major version
- Zero tolerance for untested code
- Zero tolerance for missing or incomplete documentation
- Zero tolerance for deviating from Infra spec

### Workflow (New Features)

1. **Read Infra spec section completely** - Understand the algorithm/data structure
2. **Map to Zig types** - Use type mapping guide in `whatwg_compliance` skill
3. **Write tests first** - Test all algorithm steps and edge cases
4. **Implement precisely** - Follow spec steps exactly, numbered comments
5. **Verify** - No leaks, all tests pass
6. **Document** - Inline docs with Infra spec references
7. **Update CHANGELOG.md** - Document what was added
8. **Pre-commit checks** - Run `zig fmt`, tests, review diff (see `code_quality_checklist` skill)

### Workflow (Bug Fixes)

1. **Write failing test** that reproduces the bug
2. **Check spec** - Verify what spec says should happen
3. **Fix the bug** with minimal code change
4. **Verify** all tests pass (including new test)
5. **Update** CHANGELOG.md if user-visible
6. **Pre-commit checks** - Run `zig fmt`, tests, review diff (see `code_quality_checklist` skill)

### Workflow (Committing Code) ⭐

**ALWAYS complete these steps before `git commit`:**

```bash
# 1. Format code
zig fmt src/ benchmarks/ tests/ build.zig

# 2. Run tests
zig build test --summary all

# 3. Verify build
zig build

# 4. Review changes
git diff --staged

# 5. Commit with meaningful message
git commit -m "Clear description of what and why"
```

See `skills/code_quality_checklist/SKILL.md` for complete checklist.

---

## Memory Tool Usage

Use Claude's memory tool to persist knowledge across sessions:

**Store in memory:**
- Completed Infra features with implementation dates
- Design decisions and architectural rationale
- Performance optimization notes
- Complex spec interpretation notes
- Known gotchas and edge cases

**Memory directory structure:**
```
memory/
├── completed_features.json
├── design_decisions.md
└── spec_interpretations.md
```

---

## Quick Reference

### Infra → Zig Type Mapping

| Infra Type | Zig Type | Notes |
|------------|----------|-------|
| `list` | `ArrayList(T)` | Mutable dynamic array |
| `ordered map` | `OrderedMap(K, V)` | Custom implementation (preserves insertion order) |
| `ordered set` | `OrderedSet(T)` | Custom implementation on ArrayList |
| `string` | `[]const u8` | UTF-8 byte sequence |
| `byte sequence` | `[]const u8` | Raw bytes, no UTF-8 assumption |
| `boolean` | `bool` | true/false |
| `null` | `null` | Null value |
| `code point` | `u21` | Unicode code point U+0000 to U+10FFFF |
| `byte` | `u8` | Single byte 0x00 to 0xFF |
| `struct` | `struct { ... }` | Zig struct with named fields |
| `tuple` | `struct { ... }` | Zig struct with ordered fields |

### Common Infra Operations

```zig
// Lists (Infra §5.1)
try list.append(item);           // append
try list.insert(0, item);        // prepend
_ = list.orderedRemove(index);  // remove
for (list.items) |item| { }     // for each

// Ordered Maps (Infra §5.2)
try map.set(key, value);  // set
const val = map.get(key); // get (returns ?Value)
map.remove(key);          // remove
for (map.entries()) |entry| { } // for each

// Strings (Infra §4.7)
const lower = try asciiLowercase(allocator, string);
const stripped = try stripNewlines(allocator, string);
const split = try splitOnCommas(allocator, string);

// JSON (Infra §6)
const value = try parseJsonString(allocator, json_string);
const json = try serializeInfraValue(allocator, infra_value);

// Base64 (Infra §7)
const encoded = try forgivingBase64Encode(allocator, data);
const decoded = try forgivingBase64Decode(allocator, encoded_string);
```

### Common Errors

```zig
pub const InfraError = error{
    // Parsing errors
    InvalidJson,
    InvalidBase64,
    InvalidCodePoint,
    
    // Algorithm errors
    IndexOutOfBounds,
    KeyNotFound,
    InvalidInput,
    
    // Memory errors
    OutOfMemory,
};
```

---

## File Organization

```
skills/
├── communication_protocol/  # ⭐ Ask clarifying questions when unclear
├── code_quality_checklist/  # ⭐ Pre-commit requirements (zig fmt, tests, review)
├── whatwg_compliance/       # Infra spec, type mappings, algorithms
├── zig_standards/           # Zig idioms, memory patterns, errors
├── testing_requirements/    # Test patterns, coverage, TDD
├── performance_optimization/# Primitive optimization patterns
├── documentation_standards/ # Doc format, CHANGELOG, README
└── browser_benchmarking/    # Browser research, inline storage decisions

memory/                      # Persistent knowledge (memory tool)
├── completed_features.json
├── design_decisions.md
└── spec_interpretations.md

tests/
└── unit/                    # Unit tests for primitives

src/                         # Source code
├── list.zig                 # List operations (§5.1)
├── map.zig                  # Ordered map operations (§5.2)
├── set.zig                  # Ordered set operations (§5.1.3)
├── string.zig               # String operations (§4.7)
├── bytes.zig                # Byte sequence operations (§4.5)
├── json.zig                 # JSON parsing/serialization (§6)
├── base64.zig               # Base64 encoding/decoding (§7)
├── namespaces.zig           # Namespace URIs (§8)
└── ...

Root:
├── README.md
├── CHANGELOG.md
├── CONTRIBUTING.md
├── AGENTS.md (this file)
└── ... (build files)
```

---

## Zero Tolerance For

- **Committing without running `zig fmt`** ⭐ (see `code_quality_checklist` skill)
- **Committing with failing tests** ⭐
- **Committing code that doesn't compile** ⭐
- Memory leaks (test with `std.testing.allocator`)
- Breaking changes without major version bump
- Untested code
- Missing documentation
- Undocumented CHANGELOG entries
- **Deviating from Infra spec algorithms**
- **Adding domain-specific features** (keep it pure primitives)
- **Using grep instead of reading complete specs**
- **Missing spec references** (must cite Infra spec section)

---

## When in Doubt

1. **ASK A CLARIFYING QUESTION** ⭐ - Don't assume, just ask (one question at a time)
2. **RUN PRE-COMMIT CHECKS** ⭐ - Before every commit: `zig fmt`, tests, review diff
3. **Read the Infra spec section completely** - Context matters
4. **Check the type mapping** - Use `whatwg_compliance` skill
5. **Load relevant skills** - Get specialized guidance
6. **Look at existing tests** - See patterns
7. **Follow the Golden Rules** - Especially algorithm precision

---

## Infra Standard Reference

**Official Spec**: https://infra.spec.whatwg.org/

**Key Sections**:
- §3 Algorithms - How to declare and write algorithms
- §4 Primitive data types - Nulls, booleans, numbers, bytes, strings
- §5 Data structures - Lists, maps, sets, stacks, queues, structs
- §6 JSON - Parsing and serialization
- §7 Forgiving base64 - Encoding and decoding
- §8 Namespaces - HTML, MathML, SVG, etc.

**Reading Guide**:
1. Read the section introduction (context)
2. Read all algorithm steps (don't skip)
3. Check cross-references (other sections)
4. Understand why, not just what

---

**Quality over speed.** Take time to do it right. The codebase is production-ready and must stay that way.

**Skills provide the details.** This file coordinates. Load skills for deep expertise.

**Infra is the foundation.** Other specs depend on it being correct. Precision matters.

**Thank you for maintaining the high quality standards of this project!** 🎉
