# Skill: Summary Documentation Guidelines

**Purpose**: Ensure analysis, planning, and completion documents are organized in `summaries/` directory, not project root.

---

## ⚠️ CRITICAL ENFORCEMENT RULE

**ABSOLUTELY NEVER create summary/analysis/planning/completion documents in the project root.**

**VIOLATION EXAMPLES** (these should NEVER exist in root):
- ❌ `PHASE_*_SUMMARY.md`
- ❌ `PHASE_*_COMPLETE.md`
- ❌ `SESSION_*.md`
- ❌ `*_ANALYSIS.md`
- ❌ `*_PLAN.md`
- ❌ `GAP_ANALYSIS*.md`
- ❌ `*_STATUS.md`
- ❌ `*_REPORT.md`
- ❌ `*_IMPLEMENTATION.md` (unless core design doc)

**ALL these MUST go in `summaries/` subdirectories.**

---

## Core Rule

**NEVER create analysis, planning, or completion documents in the project root.**

All temporary/working documents MUST go in `summaries/` subdirectories.

---

## Project Root - KEEP ONLY These Files

**Documentation** (user-facing, permanent):
- ✅ `README.md` - Project overview, quick start, API basics
- ✅ `CHANGELOG.md` - Version history per Keep a Changelog format
- ✅ `CONTRIBUTING.md` - Contribution guidelines
- ✅ `AGENTS.md` - Agent/AI assistant guidelines
- ✅ `LICENSE` - Software license
- ✅ `JS_BINDINGS.md` - JavaScript binding specification

**Build/Config** (essential):
- ✅ `build.zig` - Zig build configuration
- ✅ `build.zig.zon` - Zig package manager config
- ✅ `.gitignore` - Git ignore patterns

**Everything else goes in subdirectories!**

---

## Summaries Directory Structure

```
summaries/
├── analysis/          # Current performance/architecture analysis
│   ├── COMPLEX_SELECTOR_RESULTS.md
│   ├── DOM_CONSTRUCTION_COMPARISON.md
│   ├── PERFORMANCE_SUMMARY.md
│   └── BROWSER_SELECTOR_IMPLEMENTATION_ANALYSIS.md
│
├── plans/             # Implementation plans (current/active)
│   └── COMPLEX_SELECTOR_OPTIMIZATION_PLAN.md
│
├── completion/        # Phase completion reports (recent)
│   ├── PHASE1_2_COMPLETE.md
│   └── PHASE2_1_COMPLETE.md
│
├── sessions/          # Session summaries (historical)
│   ├── SESSION_SUMMARY_2025-10-17.md
│   ├── SESSION_SUMMARY_2025-10-17_PART2.md
│   └── CONVERSATION_SUMMARY.md
│
└── obsolete/          # Superseded documents (archive)
    ├── PHASE1_COMPLETE.md
    ├── GETELEMENTBYID_ANALYSIS.md
    └── ... (old analysis/plans)
```

---

## When to Create Documents

### Analysis Documents → `summaries/analysis/`

**Create when:**
- Analyzing performance results
- Comparing implementations (Zig vs browsers)
- Deep-diving into architecture
- Researching optimizations

**Examples:**
- `PERFORMANCE_SUMMARY.md` - Current performance across all benchmarks
- `COMPLEX_SELECTOR_RESULTS.md` - Results of complex selector benchmarks
- `DOM_CONSTRUCTION_COMPARISON.md` - Zig vs browser construction comparison

**Naming convention:**
- `{TOPIC}_{TYPE}.md` where TYPE = RESULTS | ANALYSIS | COMPARISON
- Use UPPERCASE with underscores
- Be specific (not generic like "ANALYSIS.md")

### Planning Documents → `summaries/plans/`

**Create when:**
- Planning a feature implementation
- Designing an optimization strategy
- Outlining a refactoring approach
- Creating implementation roadmap

**Examples:**
- `COMPLEX_SELECTOR_OPTIMIZATION_PLAN.md`
- `ARENA_ALLOCATOR_IMPLEMENTATION_PLAN.md`
- `MUTATION_OBSERVER_DESIGN.md`

**Naming convention:**
- `{FEATURE}_PLAN.md` or `{FEATURE}_DESIGN.md`
- Use UPPERCASE with underscores
- Include what's being planned

### Completion Reports → `summaries/completion/`

**Create when:**
- Completing a major phase
- Finishing a significant feature
- Documenting optimization results
- Reporting benchmark improvements

**Examples:**
- `PHASE1_2_COMPLETE.md` - appendChild fast path completion
- `PHASE2_1_COMPLETE.md` - Arena allocator completion
- `COMPLEX_SELECTORS_COMPLETE.md`

**Naming convention:**
- `PHASE_{N}_COMPLETE.md` or `{FEATURE}_COMPLETE.md`
- Use UPPERCASE with underscores
- Clear indication of completion
- **ALWAYS in `summaries/completion/`, NEVER in root**

### Session Summaries → `summaries/sessions/`

**Create when:**
- Ending a work session
- Documenting conversation progress
- Creating handoff notes for next session

**Examples:**
- `SESSION_SUMMARY_2025-10-17.md`
- `SESSION_PHASE10_COMPLETE.md`
- `CONVERSATION_SUMMARY.md`

**Naming convention:**
- `SESSION_SUMMARY_{DATE}.md` for date-specific
- `SESSION_PHASE{N}_COMPLETE.md` for phase completion sessions
- `SESSION_SUMMARY_{DATE}_PART{N}.md` for multi-part sessions
- Include ISO date format (YYYY-MM-DD)
- **ALWAYS in `summaries/sessions/`, NEVER in root**

### Obsolete Documents → `summaries/obsolete/`

**Move here when:**
- Document superseded by newer version
- Analysis no longer relevant (old results)
- Plan completed and documented in completion report
- Historical reference only

**Examples:**
- Old phase completion reports (PHASE1_COMPLETE after PHASE1_2_COMPLETE exists)
- Superseded analysis (GETELEMENTBYID_ANALYSIS after optimization complete)
- Old optimization strategies

**Don't delete** - Keep for historical reference, but mark as obsolete.

---

## What NOT to Create

### ❌ Don't Create in Root

- ❌ `PERFORMANCE_ANALYSIS.md` → `summaries/analysis/PERFORMANCE_SUMMARY.md`
- ❌ `OPTIMIZATION_PLAN.md` → `summaries/plans/FEATURE_OPTIMIZATION_PLAN.md`
- ❌ `SESSION_NOTES.md` → `summaries/sessions/SESSION_SUMMARY_DATE.md`
- ❌ `RESULTS.md` → `summaries/analysis/FEATURE_RESULTS.md`

### ❌ Don't Create Duplicates

**Before creating**, check if similar document exists:
- Search `summaries/` for related documents
- Update existing document instead of creating new
- Consolidate information rather than fragmenting

### ❌ Don't Create Generic Names

**Bad:**
- `ANALYSIS.md` - Too vague
- `RESULTS.md` - What results?
- `PLAN.md` - Plan for what?
- `NOTES.md` - Notes about what?

**Good:**
- `COMPLEX_SELECTOR_RESULTS.md` - Specific
- `ARENA_ALLOCATOR_PLAN.md` - Clear what's planned
- `SESSION_SUMMARY_2025-10-17.md` - Dated and typed

---

## Maintenance Rules

### Periodic Cleanup

**Every 5-10 sessions:**
1. Review `summaries/analysis/` - Move outdated to obsolete
2. Review `summaries/plans/` - Move completed to obsolete
3. Review `summaries/completion/` - Keep recent (last 3-5), move older to obsolete
4. Review `summaries/sessions/` - Keep recent (last 10), move older to obsolete

### Moving to Obsolete

**Don't delete**, move to `summaries/obsolete/`:
```bash
mv summaries/analysis/OLD_ANALYSIS.md summaries/obsolete/
```

**Add note in moved file:**
```markdown
# [OBSOLETE] Old Analysis Name

**Status**: OBSOLETE - Superseded by newer analysis  
**Date**: YYYY-MM-DD  
**Reason**: Replaced by {NEW_DOCUMENT_NAME}

---

[Original content...]
```

### Consolidation

**When multiple documents cover same topic:**
1. Create new consolidated document
2. Move old documents to obsolete
3. Reference consolidation in old documents
4. Update any links/references

---

## Git Ignore

The `summaries/` directory is gitignored:

```gitignore
# Summaries and plans to ignore
summaries/
```

**Why?**
- Temporary working documents
- Session-specific notes
- May contain draft/incomplete information
- Reduces repo clutter
- Historical documents available locally

**Exception**: If document becomes permanent reference, move to appropriate location:
- Architecture guide → `docs/architecture/`
- API specification → `docs/api/`
- Design patterns → `docs/design/`

---

## Checklist for Creating Documents

Before creating a new document, verify:

- [ ] Is this temporary/working document? → `summaries/`
- [ ] Is this permanent/user-facing? → Root or `docs/`
- [ ] Does similar document already exist? → Update existing
- [ ] Is the name specific and clear?
- [ ] Am I using the correct subdirectory?
- [ ] Have I checked `summaries/obsolete/` for related old docs?

---

## Examples

### ✅ Good Document Creation Flow

```
User: "Analyze the querySelector performance results"

Agent thinks:
- This is analysis → summaries/analysis/
- Topic is querySelector performance → QUERYSELECTOR_PERFORMANCE_RESULTS.md
- Check if exists... no
- Create summaries/analysis/QUERYSELECTOR_PERFORMANCE_RESULTS.md
```

### ✅ Good Document Update Flow

```
User: "Update the complex selector results with new benchmarks"

Agent thinks:
- Check summaries/analysis/COMPLEX_SELECTOR_RESULTS.md
- File exists! Update instead of creating new
- Add new benchmark results to existing document
```

### ❌ Bad Document Creation Flow

```
User: "Create a performance summary"

Agent (WRONG):
- Creates PERFORMANCE_SUMMARY.md in root ❌

Agent (CORRECT):
- Creates summaries/analysis/PERFORMANCE_SUMMARY.md ✅
```

---

## Quick Reference

| Document Type | Location | Naming Pattern |
|--------------|----------|----------------|
| Analysis | `summaries/analysis/` | `{TOPIC}_{RESULTS\|ANALYSIS\|COMPARISON}.md` |
| Planning | `summaries/plans/` | `{FEATURE}_{PLAN\|DESIGN}.md` |
| Completion | `summaries/completion/` | `{PHASE\|FEATURE}_COMPLETE.md` |
| Sessions | `summaries/sessions/` | `SESSION_SUMMARY_{DATE}[_PART{N}].md` |
| Obsolete | `summaries/obsolete/` | `[OBSOLETE]_{ORIGINAL_NAME}.md` |

---

## Summary

**Golden Rule**: Keep project root clean. Only permanent, user-facing documentation belongs in root. Everything else goes in `summaries/` subdirectories.

**When in doubt**: Put it in `summaries/`. Better to have working documents organized than cluttering the root.

**Maintenance**: Regularly move old documents to `obsolete/` to keep active directories clean.
