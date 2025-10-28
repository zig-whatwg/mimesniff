# Code Quality Checklist - Pre-Commit Requirements

**When to use:** ALWAYS before committing code changes.

## Critical Rule: NEVER Commit Without These Checks

Before ANY `git commit`, you MUST complete ALL of the following checks in order:

### 1. ✅ Run `zig fmt`

**ALWAYS run `zig fmt` on all modified Zig files before committing.**

```bash
# Format all Zig code
zig fmt src/ benchmarks/ tests/ build.zig

# OR check if formatting is needed (no output = already formatted)
zig fmt --check src/ benchmarks/ tests/ build.zig
```

**Why:** Zig has a canonical code format. Unformatted code:
- Creates unnecessary diff noise
- Fails CI checks
- Wastes reviewer time
- Looks unprofessional

**When formatting fails:** If `zig fmt --check` outputs filenames, those files need formatting. Run `zig fmt` without `--check` to auto-format them.

### 2. ✅ Run All Tests

```bash
# Run full test suite
zig build test --summary all

# Verify:
# - All tests pass (N/N tests passed)
# - No memory leaks
# - No panics or crashes
```

**Why:** Broken tests mean broken code. Never commit broken tests.

### 3. ✅ Run Type Check / Build

```bash
# Verify code compiles
zig build

# For libraries (no executable), just ensure tests compile
zig build test
```

**Why:** Code that doesn't compile breaks the build for everyone.

### 4. ✅ Check Git Status

```bash
git status
```

**Verify:**
- No unintended files staged (secrets, build artifacts, editor files)
- All intended changes are staged
- No accidentally staged debugging code

### 5. ✅ Review Diff Before Committing

```bash
git diff --staged
```

**Look for:**
- Debug print statements (`std.debug.print`, `console.log`, etc.)
- Commented-out code that should be removed
- TODO/FIXME comments that should be addressed
- Secrets, API keys, passwords, tokens
- Large files that shouldn't be committed

### 6. ✅ Write Meaningful Commit Message

**Good commit message:**
```
Fix MIDI pattern byte length bug

The MIDI pattern was 9 bytes but should be 8 bytes according to spec.
This caused pattern matching assertion failures.
```

**Bad commit message:**
```
fix stuff
```

### 7. ✅ Run Linter (If Available)

```bash
# If project has a linter configured
zig build lint

# Or check for common issues
grep -r "TODO\|FIXME\|XXX\|HACK" src/
```

## Pre-Commit Checklist Template

Copy this checklist for every commit:

```
[ ] zig fmt (all files formatted)
[ ] zig build test (all tests pass)
[ ] zig build (compiles successfully)
[ ] git status (no unintended files)
[ ] git diff --staged (reviewed all changes)
[ ] Commit message (clear and meaningful)
[ ] No debug code, TODOs, or secrets
```

## Common Mistakes

### ❌ "I'll format it later"
**NO.** Format before committing. Always.

### ❌ "It's just a small change"
**NO.** Even small changes need formatting and tests.

### ❌ "CI will catch it"
**NO.** CI is a safety net, not an excuse to skip local checks.

### ❌ "I'm in a hurry"
**NO.** Taking 30 seconds to run checks saves hours of debugging later.

## Automation

Consider adding a git pre-commit hook:

```bash
#!/bin/sh
# .git/hooks/pre-commit

echo "Running pre-commit checks..."

# Format check
echo "Checking zig fmt..."
zig fmt --check src/ benchmarks/ tests/ build.zig || {
    echo "ERROR: Code is not formatted. Run: zig fmt src/ benchmarks/ tests/ build.zig"
    exit 1
}

# Run tests
echo "Running tests..."
zig build test || {
    echo "ERROR: Tests failed"
    exit 1
}

echo "✅ Pre-commit checks passed"
```

## Integration with AI Coding Sessions

**For AI agents (like Claude):**

When you are about to commit code, you MUST:

1. **Announce:** "Running pre-commit checks..."
2. **Run:** All checks from the checklist above
3. **Report:** Results of each check
4. **Fix:** Any issues found
5. **Re-run:** Checks after fixes
6. **Only then:** Commit

**Example workflow:**

```
AI: "I'm ready to commit. Running pre-commit checks..."

AI: [Runs zig fmt --check]
AI: "❌ Formatting issues found in src/mime_constants.zig"
AI: [Runs zig fmt src/]
AI: "✅ Formatting fixed"

AI: [Runs zig build test]
AI: "✅ All 151 tests passed, no memory leaks"

AI: [Runs zig build]
AI: "✅ Build successful"

AI: [Checks git diff]
AI: "✅ No debug code or secrets in diff"

AI: "All pre-commit checks passed. Committing now..."
AI: [Commits with meaningful message]
```

## Why This Matters

**Code quality is not optional.** These checks:

- Prevent bugs from reaching production
- Keep the codebase maintainable
- Respect other developers' time
- Demonstrate professionalism
- Avoid embarrassing "oops" commits

## Zero Tolerance

This project has **zero tolerance** for:

- ❌ Unformatted code
- ❌ Failing tests
- ❌ Code that doesn't compile
- ❌ Secrets in commits
- ❌ Debug code in commits
- ❌ Meaningless commit messages

**Follow the checklist. Every time. No exceptions.**

---

**Remember:** The 2 minutes you spend on pre-commit checks saves 2 hours of debugging later.
