---
title: "Hunting for DOMPurify CVEs with Evolutionary Algorithms: Methodology and Architecture"
date: 2026-02-07T12:00:00-00:00
author: "trace37 labs"
tags: ["security", "XSS", "DOMPurify", "fuzzing", "evolutionary-algorithms", "CVE", "research"]
categories: ["Security Research"]
description: "A novel methodology for discovering XSS sanitization bypasses using evolutionary algorithms to systematically explore DOMPurify's attack surface"
draft: true
---

**Target**: DOMPurify 3.2.4+ core library bypass
**Audience**: Security researchers, bug hunters, XSS specialists

---

<br>

## Executive Summary

This paper presents a novel methodology for discovering XSS sanitization bypasses using evolutionary algorithms. We describe a large-scale evolutionary fuzzing system targeting DOMPurify, the industry-standard XSS sanitization library (30M+ weekly npm downloads). Our goal is to discover **zero-day CVEs in DOMPurify's core sanitization logic** — not application misconfigurations, but genuine bypasses that work against `DOMPurify.sanitize()` with default settings.

**Why this matters**: Core DOMPurify bypasses continue to be discovered (CVE-2025-26791 in January 2025, CVE-2024-45801 in September 2024), demonstrating that even mature, battle-tested sanitizers have undiscovered attack surfaces. A successful core bypass affects every application using DOMPurify and carries significant impact:

- **CVE assignment** with industry-wide disclosure
- **Bug bounties** (GitHub Security Lab, HackerOne, etc.)
- **Immediate security patches** affecting 30M+ weekly downloads
- **Research recognition** in the XSS/mXSS research community

This paper documents our hypothesis, methodology, and architecture. We describe how evolutionary algorithms can systematically explore the vast attack surface of modern HTML sanitizers by treating vulnerability discovery as an optimization problem rather than binary testing.

---

<br>

## Table of Contents

1. [Background: Why DOMPurify?](#background)
2. [Research Foundation & Prior Art](#research-foundation)
3. [Attack Surface Analysis](#attack-surface)
4. [Evolutionary Fuzzing Architecture](#architecture)
5. [Fitness Functions: Measuring Partial Success](#fitness)
6. [Mutation Operators: The 5-Rotor Methodology](#mutations)
7. [Implementation Details](#implementation)
8. [Expected Performance Characteristics](#performance)
9. [Research Outcomes and Future Directions](#outcomes)

---

<br>

## <a name="background"></a>1. Background: Why DOMPurify?

### The XSS Problem

Cross-Site Scripting (XSS) remains one of the most prevalent web security vulnerabilities. Despite decades of research, new bypasses emerge constantly as browsers evolve, parsers get updated, and edge cases multiply. Modern web applications face a critical challenge: **how do you safely accept user-generated HTML without introducing XSS vulnerabilities?**

### DOMPurify's Role

DOMPurify (created by Cure53) is the de facto standard for client-side HTML sanitization. It's used by:

- **GitHub** (Markdown rendering, issue comments)
- **Notion** (rich text editor)
- **Slack** (message formatting)
- **Discord** (embed sanitization)
- **WordPress Gutenberg** (block editor)
- **Hundreds of major SaaS platforms**

With 30M+ weekly downloads and integration into critical infrastructure, a DOMPurify bypass has massive blast radius.

### Why Core Bypasses Are Rare (But Not Impossible)

DOMPurify has been battle-tested for years. Most discovered "bypasses" are actually **application-level mistakes**:

- Misconfigured hooks (`forceKeepAttr` vulnerabilities)
- Post-sanitization string manipulation (TinyMCE CVE-2023-48219)
- Wrong configuration options (`SAFE_FOR_TEMPLATES`, `ALLOW_UNKNOWN_PROTOCOLS`)

**But core bypasses DO happen:**

- **CVE-2025-26791** (January 2025): Template literal regex bypass in DOMPurify 3.2.3
- **CVE-2024-45801** (September 2024): Namespace confusion in SVG/MathML handling
- **CVE-2023-51467** (December 2023): Parser differential in form/table fostering

Each of these worked against **default configuration** with no application errors. That's what we're hunting for.

---

<br>

## <a name="research-foundation"></a>2. Research Foundation & Prior Art

Our approach builds on three pillars of existing research:

### 2.1 The Enigma XSS Tool (5-Rotor Methodology)

Our [Enigma tool](/blog/enigma-xss-engine/) uses a **5-Rotor cascade approach** to systematically explore XSS attack space:

1. **Context** (WHERE): Template literal, attribute, script context, innerHTML
2. **Blockers** (WHAT blocks execution): WAF rules, sanitizers, CSP
3. **Encoding** (HOW to bypass): HTML entities, URL encoding, Unicode
4. **Structure** (PAYLOAD structure): Tag nesting, attribute injection
5. **Execution** (FINAL trigger): Event handlers, javascript: URLs, script tags

**Key insight from Gareth Heyes, upon which the [Enigma XSS tool](/blog/enigma-xss-engine/) is built**: "Build on what works" — track **partial successes** (what survives sanitization even if it doesn't execute) and evolve from there. Don't treat payloads as binary pass/fail.

### 2.2 DOMPurify Harness Research (Our Prior Work)

We previously built a structured harness testing DOMPurify against:

- **WRAPPERS × TAGS × EVENTS × ENCODINGS** combinatorial explosion
- Known mXSS patterns (form/mathml nesting, SVG foreignObject, table fostering)
- Null byte parser differentials (6,841 mismatches found between browsers and sanitizers)

**Result**: Found 3,269 structural mutations where `<form><math><mtext></form><form>` causes DOM tree changes, but no confirmed XSS. This gave us a **foothold** — partial success that evolution can amplify.

### 2.3 mizu.re Research on DOMPurify Misconfigurations

Kévin GERVOT's (mizu.re) research catalogs real-world DOMPurify bypasses:

- Most are **application bugs**, not library bugs
- Common patterns: `afterSanitizeAttributes` hooks that re-add dangerous attributes
- Post-processing vulnerabilities (jQuery ≤3.4.1, entity unescaping)

**Our divergence**: We're intentionally **NOT** targeting application misconfigurations. Those are valuable for bug bounties but don't earn CVEs. We want the library itself.

---

<br>

## <a name="attack-surface"></a>3. Attack Surface Analysis

### 3.1 The Triple-Track Strategy

We divide the attack surface into three evolutionary tracks:

#### **Track 1: Core mXSS (80% of effort)** 🎯 PRIMARY TARGET

**Goal**: Find mutation XSS (mXSS) in DOMPurify's core sanitization, no hooks/configs.

**Attack vectors**:

1. **Null byte parser differentials**: Null bytes (`\x00`) expose parser inconsistencies between sanitizers and browsers. In prior research, we systematically tested null byte insertion at every character position across a corpus of 500+ XSS vectors (classical payloads, mXSS patterns, and polyglots). This brute-force enumeration revealed 6,841 positions where DOMPurify's sanitized output differed from browser-parsed output when a null byte was inserted. While not all differences are exploitable, they indicate parser boundary conditions worth exploring.

   **Example Null Byte Position Analysis**:

   | Position | Original | With Null Byte | DOMPurify Output | Browser Output | Divergence |
   |----------|----------|----------------|------------------|----------------|------------|
   | Tag name | `<script>` | `<scr\x00ipt>` | (stripped) | `<scr ipt>` (text) | ✅ |
   | Protocol | `javascript:alert(1)` | `java\x00script:alert(1)` | (blocked) | `java` (truncated) | ✅ |
   | Event handler | `onerror=alert(1)` | `on\x00error=alert(1)` | (blocked) | `on error=` (invalid) | ✅ |
   | Mid-attribute | `<img src=x onerror=1>` | `<img src=x\x00 onerror=1>` | `<img src="x">` | `<img src="x">` | ❌ |

   The divergence column indicates where sanitizer and browser disagree on parsing. Even "safe" divergences reveal edge cases that, when combined with other mutations (namespace confusion, deep nesting), may become exploitable.

   Our evolutionary fuzzer builds on this research with 20+ targeted null byte mutation operators that insert `\x00` at critical positions:
   - **Tag names**: `<scr\x00ipt>`, `<\x00form>` (mid-token disruption)
   - **Attribute names**: `on\x00error=`, `data-\x00bind=` (event handler splitting)
   - **Attribute values**: `java\x00script:`, `"value\x00"` (protocol parsing)
   - **Tag boundaries**: `<\x00/form>`, `<img\x00>` (bracket handling)

   Rather than brute-forcing all 6,841 positions each generation, evolution explores this space intelligently: high-fitness payloads with null bytes in promising positions breed more variants, while unsuccessful positions are naturally selected against. Over 50,000 generations, the algorithm will explore hundreds of thousands of null byte combinations.

2. **Namespace confusion**: SVG and MathML have different parsing rules than HTML. DOMPurify must handle:
   - `<svg><foreignObject>` (switches back to HTML parsing inside SVG)
   - `<math><annotation-xml>` (similar namespace switch)
   - Case-sensitivity differences (SVG nodeName casing)

3. **Deep nesting + innerHTML reparse**: The classic mXSS pattern:
   ```html
   <form><math><mtext></form><form><img src=x onerror=alert(1)></form>
   ```
   Parser moves elements during tree construction. If DOMPurify sanitizes the *input* tree but the *output* tree mutates during reparse, XSS slips through.

4. **Unicode normalization bypasses**:
   - Homoglyphs (Cyrillic 'o' vs Latin 'o')
   - Zero-width characters (`\u200B`, `\uFEFF`) mid-token
   - Ligatures that change after `toUpperCase()`: `ﬆ` → `ST`

5. **DOM clobbering + sanitization interaction**: Clobber DOMPurify's internal properties (`attributes`, `innerHTML`) with crafted DOM structures.

**Why 80%**: Core bypasses are rare but **high-value**. CVE assignment and substantial bug bounties across platforms.

#### **Track 2: Hook Bypasses (15% of effort)** 🎯 FALLBACK

**Goal**: Find bypasses in common application hooks (still valuable, not CVE-level).

**Patterns**:
- `forceKeepAttr` (≤3.1.5 vulnerability pattern)
- `afterSanitizeAttributes` + `setAttribute()` injection
- Rails UJS data attributes (`data-remote="true"`)
- htmx/Alpine.js framework attributes

**Why 15%**: These don't qualify as CVEs (app bugs, not library bugs) but still earn meaningful bug bounties.

#### **Track 3: Integration Bugs (5% of effort)** 🎯 VALIDATION

**Goal**: Post-sanitization vulnerabilities (app does bad things AFTER DOMPurify).

**Patterns**:
- Entity unescaping: `&lt;script&gt;` → `<script>` after DOMPurify
- U+FFFD stripping: `java�script:` → `javascript:` after sanitization
- jQuery ≤3.4.1 (503+ nested tags vulnerability)

**Why 5%**: Validates our methodology works, even if not the primary target.

### 3.2 Success Criteria

We define success at **four levels**:

| Level | Description | Impact | Value |
|-------|-------------|--------|-------|
| **🏆 CVE** | Core library bypass, default config | Industry-wide | High bounties + CVE credit |
| **🥈 Hook bypass** | Application misconfiguration | Platform-specific | Moderate bounties |
| **🥉 Integration bug** | Post-processing vulnerability | Platform-specific | Small bounties |
| **📊 Research data** | Novel attack patterns (no XSS) | Academic/research | Reputation |

---

<br>

## <a name="architecture"></a>4. Evolutionary Fuzzing Architecture

### 4.1 Why Evolution?

Traditional fuzzing approaches XSS payloads as **binary**: execute or don't execute. But this misses the gradient:

```
Random payload → DOMPurify → (empty string)
❌ Failure. Discard.

Random payload → DOMPurify → <form><math>...</math></form>
🤔 Partial success! Structure survived! Build on this!
```

Evolution doesn't just test payloads — it **breeds better payloads** from successful patterns.

### 4.2 The Evolutionary Loop

```
┌─────────────────────────────────────────────────┐
│  Generation N (200,000 payloads)                │
│   ├─ Track 1: 160,000 core-mxss payloads       │
│   ├─ Track 2:  30,000 hook-bypass payloads     │
│   └─ Track 3:  10,000 integration payloads     │
└─────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────┐
│  Fitness Evaluation (JSDOM + DOMPurify)         │
│   Each payload gets scored 0.0-1.0:             │
│   - 0.0: Completely blocked                     │
│   - 0.4: Structural survival (form/math nested) │
│   - 0.8: Dangerous tags survive                 │
│   - 1.0: XSS CONFIRMED → CVE FOUND!             │
└─────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────┐
│  Selection (Tournament - Top 20%)               │
│   Pick strongest payloads as parents            │
└─────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────┐
│  Crossover (60% of breeding)                    │
│   Parent 1: <form><math>...</math></form>       │
│   Parent 2: <svg onload=alert(1)>               │
│   Child:    <form><math><svg onload=alert(1)>>  │
└─────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────┐
│  Mutation (80% mutation rate)                   │
│   Add null bytes, change encodings, nest deeper │
└─────────────────────────────────────────────────┘
                      ↓
               Generation N+1
```

### 4.3 Population Management

**Per-Track Populations:**
- **Track 1 (Core mXSS)**: 160,000 payloads/generation (80%)
  - Null byte mutations: 40,000
  - Unicode normalization: 30,000
  - Namespace confusion: 30,000
  - Deep nesting: 30,000
  - DOM clobbering: 20,000
  - Classical patterns: 10,000

- **Track 2 (Hook Bypass)**: 30,000 payloads/generation (15%)
- **Track 3 (Integration)**: 10,000 payloads/generation (5%)

**Selection Strategy**: Tournament selection (groups of 5, pick strongest, repeat until 20% of population selected as parents)

**Breeding Strategy**:
- 60% crossover (combine features from two parents)
- 40% clone (copy parent with mutations)
- 80% mutation rate after breeding

**Elitism**: Top 1% preserved unchanged generation-to-generation (prevents losing high-fitness specimens)

### 4.4 Convergence Criteria

**Stop conditions**:
1. **Success**: Fitness = 1.0 (XSS confirmed)
2. **Plateau**: No improvement for 50 generations
3. **Collapse**: Diversity < 10% (premature convergence)
4. **Limit**: 50,000 generations maximum

---

<br>

## <a name="fitness"></a>5. Fitness Functions: Measuring Partial Success

The fitness function is the **heart** of evolutionary fuzzing. It quantifies "how close are we to XSS?" on a 0-1 scale.

### 5.1 Track 1: Core mXSS Fitness

```typescript
interface CoreMXSSFitness {
  structural: number;         // 0-1: DOM tree mutations
  dangerous_tags: number;     // 0-1: script/iframe/svg survival
  attributes: number;         // 0-1: Event handler survival rate
  null_byte_position: number; // 0-1: Null byte in critical position
  reparse_delta: number;      // 0-1: innerHTML reparse difference
  execution: number;          // 0-1: XSS confirmed (1.0 = SUCCESS!)
 : number;             // Weighted sum
}
```

**Test 1: Structural Mutation**

```typescript
const hasFormMath = /<form[^>]*>.*<math/i.test(sanitized);
if (hasFormMath) return 0.6;  // Known foothold!
```

We know `<form><math>` causes structural mutations (3,269 found in prior research). Any payload preserving this structure gets **immediate 0.6 fitness** — a strong signal to evolution.

**Test 2: Dangerous Tags Survival** (regex-based for speed)

```typescript
if (/<script[\s>]/i.test(sanitized)) return 1.0;  // Script tag survived!
if (/<iframe[\s>]/i.test(sanitized)) return 1.0;
if (/<object[\s>]/i.test(sanitized)) return 1.0;
if (/<svg[\s>]/i.test(sanitized)) return 0.8;
if (/<style[\s>]/i.test(sanitized)) return 0.7;
if (/<form[\s>]/i.test(sanitized)) return 0.6;
```

DOMPurify should block `<script>`, `<iframe>`, `<object>`. If they survive → **high fitness**.

**Test 3: Attribute Survival Rate**

```typescript
const inputEvents = input.match(/on[a-z]+\s*=/gi) || [];
const sanitizedEvents = sanitized.match(/on[a-z]+\s*=/gi) || [];
return sanitizedEvents.length / inputEvents.length;
```

Count how many event handlers survive. `onerror`, `onload`, `ontoggle` are XSS vectors.

**Test 4: Null Byte Positioning** (CRITICAL — our 6,841 mismatches)

```typescript
const nullIndex = input.indexOf('\x00');
if (sanitized.includes('\x00')) return 1.0;  // Null byte survived!

// Check if null byte was in critical position:
const beforeNull = input.substring(nullIndex - 10, nullIndex);
const afterNull = input.substring(nullIndex + 1, nullIndex + 11);

// Mid-tag name: <scr\x00ipt>
if (/<[a-z]*/i.test(beforeNull) && /^[a-z]*>/i.test(afterNull)) return 0.9;

// Mid-event handler: on\x00error=
if (/on[a-z]*/i.test(beforeNull) && /^[a-z]*=/i.test(afterNull)) return 0.9;

// Mid-protocol: java\x00script:
if (/java/i.test(beforeNull) && /^script:/i.test(afterNull)) return 0.8;
```

Null bytes are a goldmine for parser differentials. Evolution explores the 6,841 positions identified in prior research.

**Test 5: innerHTML Reparse Delta** (mutation XSS detection)

```typescript
div1.innerHTML = sanitized;
const firstHTML = div1.innerHTML;

div2.innerHTML = firstHTML;  // Reparse!
const secondHTML = div2.innerHTML;

const sig1 = extractTagSignature(firstHTML);
const sig2 = extractTagSignature(secondHTML);

return sig1 !== sig2 ? 1.0 : 0;  // Tags changed → mutation!
```

Classic mXSS: if the DOM tree structure changes after reparsing, dangerous content might appear.

**Test 6: Execution Potential** (hybrid: regex pre-filter → DOM verification)

```typescript
// Fast path: no HTML tags → safe
if (!/<[a-zA-Z][^>]*>/.test(sanitized)) return 0;

// Fast path: no dangerous patterns → safe
if (!/on[a-z]+=|javascript:|<script|<iframe/i.test(sanitized)) return 0;

// Slow path: DOM verification (catches false positives)
divExec.innerHTML = sanitized;
if (divExec.querySelector('[onerror], [onload], [ontoggle]')) {
  return 1.0;  // Event handler is ACTUAL attribute, not text!
}
```

**Why hybrid?** Regex matches `onerror=` anywhere, including inside `<title>onerror=alert(1)</title>` (which is harmless text content). DOM verification confirms it's a real attribute on a real element.

**Weighted Total**:

```typescript
const =
  structural * 0.1 +
  dangerous_tags * 0.3 +
  attributes * 0.2 +
  null_byte_position * 0.1 +
  reparse_delta * 0.2 +
  execution * 1.0;  // If execution=1.0,=1.0 (override all)
```

**If `execution = 1.0` → we found XSS → STOP EVERYTHING.**

### 5.2 Why This Works: The Gradient

Traditional fuzzing:
```
Payload A: "random garbage" → Blocked → 0 (discard)
Payload B: "<form><math>..."  → Blocked → 0 (discard)
```

Evolutionary fuzzing:
```
Payload A: "random garbage" → Blocked → 0.0 (discard)
Payload B: "<form><math>..."  → Blocked → 0.6 (BREED FROM THIS!)
         ↓
Child 1: <form><math><img src=x onerror=alert(1)>> → 0.8 (getting closer!)
         ↓
Child 2: <form><math>\x00<img src=x onerror=alert(1)>> → 0.9 (very close!)
         ↓
Child 3: [THE MAGIC COMBINATION] → 1.0 (XSS!)
```

Evolution **climbs the fitness gradient** toward XSS.

---

<br>

## <a name="mutations"></a>6. Mutation Operators: The 5-Rotor Methodology

Inspired by Gareth Heyes, we implement **5 mutation rotors** built into the trace37 Enigma XSS tool that can be combined:

### Rotor 1: Context Wrappers (WHERE)

```typescript
const WRAPPERS = [
  p => `<form><math><mtext></form><form>{p}</form>`,  // Known foothold
  p => `<svg><foreignObject>{p}</foreignObject></svg>`,
  p => `<table><math>{p}</math></table>`,
  p => `<style><!--{p}--></style>`,
  p => `<textarea>{p}</textarea>`,
  p => `<template>{p}</template>`,
  p => `<noscript>{p}</noscript>`,
  p => `<select><math>{p}</math></select>`,
];
```

Each wrapper places the payload in a different parsing context.

### Rotor 2: Tag Variants (WHAT)

```typescript
const TAGS = [
  '<img src=x onerror=alert(1)>',
  '<svg onload=alert(1)>',
  '<details open ontoggle=alert(1)>',
  '<iframe srcdoc="<img src=x onerror=alert(1)>">',
  '<object data="javascript:alert(1)">',
  '<embed src="javascript:alert(1)">',
  '<script>alert(1)</script>',
  '<math><mi xlink:href="data:,alert(1)">',
];
```

Classical XSS vectors.

### Rotor 3: Null Byte Positioning (HOW - CRITICAL)

```typescript
const NULL_BYTE_MUTATIONS = [
  // Tag name disruption
  tag => tag.replace('<', '<\x00'),                    // <\x00form>
  tag => tag.replace(/^<([a-z]+)/, '<\x00'),        // <form\x00>

  // Attribute name disruption
  tag => tag.replace(/on([a-z]+)=/, 'on\x00='),    // on\x00error=

  // Attribute value disruption
  tag => tag.replace(/javascript:/, 'java\x00script:'), // java\x00script:

  // Closing tag disruption
  tag => tag.replace(/<\//, '<\x00/'),                // <\x00/form>
];
```

We have **20+ null byte mutation operators** targeting the 6,841 critical positions identified in prior research.

### Rotor 4: Unicode Normalization (HOW)

```typescript
const UNICODE_MUTATIONS = [
  // Character variants
  tag => tag.replace('<script', '<\u0073cript'),     // \u0073 = 's'

  // Zero-width characters
  tag => tag.replace('onerror', 'on\u200Berror'),    // Zero-width space
  tag => tag.replace('onerror', 'on\uFEFFerror'),    // BOM

  // Homoglyphs (Cyrillic vs Latin)
  tag => tag.replace('o', '\u043E'),                 // Cyrillic 'o'

  // Ligatures (toUpperCase bypass)
  tag => tag.replace('st', 'ﬆ'),                     // ﬆ → ST after toUpperCase()
];
```

### Rotor 5: Namespace Confusion

```typescript
const NAMESPACE_MUTATIONS = [
  // SVG namespace
  tag => `<svg>{tag}</svg>`,
  tag => `<svg><foreignObject>{tag}</foreignObject></svg>`,

  // MathML namespace
  tag => `<math>{tag}</math>`,
  tag => `<math><annotation-xml>{tag}</annotation-xml></math>`,

  // Cross-namespace mutation
  tag => `<svg><math>{tag}</math></svg>`,
  tag => `<table><svg>{tag}</svg></table>`,
];
```

### Cascade Combination

Each payload can undergo **multiple rotors** sequentially:

```typescript
// Start: <img src=x onerror=alert(1)>

// Rotor 1 (wrapper): <form><math><mtext></form><form><img src=x onerror=alert(1)></form>

// Rotor 3 (null byte): <form><math><mtext></form><form><img src=x on\x00error=alert(1)></form>

// Rotor 4 (unicode): <form><math><mtext></form><form><img src=x on\x00\u200Berror=alert(1)></form>

// Test fitness → if high, breed from this pattern!
```

**Combinatorial explosion**: 8 wrappers × 12 tags × 30 null mutations × 15 unicode mutations = **43,200 combinations** from base corpus alone. Evolution explores this space guided by fitness.

---

<br>

## <a name="implementation"></a>7. Implementation Details

### 7.1 Technology Stack

```
Language:   TypeScript (type safety for complex genetic algorithms)
Runtime:    Node.js 22+
DOM:        JSDOM (spec-compliant HTML5 parser via parse5)
Target:     DOMPurify 3.2.4 (latest stable)
Validation: Puppeteer (real browser confirmation)
Parallel:   Worker threads (14 workers, 16GB heap)
Storage:    JSON Lines (lineage tracking)
Dashboard:  Python HTTP server + Canvas visualization
```

### 7.2 Architecture

```
src/
├── core/
│   ├── evolution.ts           # Master evolution engine
│   ├── population.ts          # Selection, breeding, diversity
│   ├── fitness/
│   │   ├── core-mxss.ts       # Track 1 evaluator
│   │   ├── hook-bypass.ts     # Track 2 evaluator
│   │   ├── integration.ts     # Track 3 evaluator
│   │   └── worker.ts          # Parallel JSDOM evaluation
│   ├── mutation/
│   │   ├── rotors.ts          # 5 Rotor definitions
│   │   ├── null-byte.ts       # Null byte operators
│   │   └── adaptive.ts        # "Build on what works"
│   └── crossover/
│       ├── features.ts        # Extract wrapper/tag/event
│       └── recombine.ts       # Combine best features
├── corpus/
│   └── seeds/                 # Initial 600+ mXSS patterns
└── cli/
    └── run.ts                 # Campaign launcher
```

### 7.3 Performance Optimizations

**Challenge**: Evaluating 200,000 payloads per generation with JSDOM is slow.

**Solution 1: Worker Thread Parallelization**

```typescript
// 14 worker threads, each running JSDOM + DOMPurify
const workers = Array.from({ length: 14 }, () =>
  new Worker('./fitness/worker.js')
);

// Distribute 160,000 core-mxss payloads across workers
// Each gets ~11,400 payloads
// Chunked into 2,000-payload batches for progress updates
```

**Result**: **~335 evals/sec** sustained (14 workers × ~24 evals/sec/worker)

**Solution 2: Regex Pre-filtering**

Original approach (DOM-based):
```typescript
div.innerHTML = sanitized;
if (div.querySelector('script')) return 1.0;  // 9 evals/sec
```

Optimized (regex pre-filter → DOM verification):
```typescript
if (/<script[\s>]/i.test(sanitized)) {  // Fast!
  div.innerHTML = sanitized;
  if (div.querySelector('script')) return 1.0;  // Only if regex matched
}
```

**Result**: **40x speedup** (9/sec → 335/sec) while maintaining accuracy.

**Solution 3: False Positive Elimination**

Early versions produced 138 "CVEs" in Gen 0 (all false positives). Problem: regex matched dangerous patterns in text content.

Example:
```html
Input:  <svg><title><svg onerror=alert(1)></title></svg>
Output: <svg><title>&lt;svg onerror=alert(1)&gt;</title></svg>
```

DOMPurify correctly entity-encoded the inner `<svg>`, but regex matched `onerror=` in the **text content** of `<title>`.

**Fix**: DOM verification after regex match:
```typescript
if (/onerror=/i.test(sanitized)) {  // Regex pre-filter
  div.innerHTML = sanitized;
  if (div.querySelector('[onerror]')) {  // DOM verification
    return 1.0;  // Confirmed: onerror is an ATTRIBUTE, not text
  }
}
```

**Result**: Zero false positives in validation runs.

### 7.4 Lineage Tracking & Visualization

We track **payload genealogy** — which payloads bred which children:

```typescript
interface Payload {
  id: string;
  content: string;
  generation: number;
  fitness: FitnessScore;
  parent1?: string;  // Parent IDs
  parent2?: string;
  mutation?: string; // What mutation was applied
}
```

Each generation, we write top payloads to `lineage.jsonl`:

```json
{
  "gen": 5,
  "maxFitness": 0.68,
  "payloads": [
    {
      "id": "a3f7b2c9",
      "fitness": 0.68,
      "parent1": "d4e8a1f3",
      "parent2": "b7c2e9a1",
      "wrapper": "form+math",
      "content": "<form><math><mtext></form><form><img...>"
    }
  ]
}
```

**Phylogenetic tree visualization** at `http://localhost:8321/tree`:

- Each generation = column
- Each payload = node (radius based on fitness, color based on wrapper family)
- Bezier curves connect children to parents
- Hover shows full payload + fitness breakdown

This lets us **watch evolution in action** — which payload families dominate, which mutations succeed, how fitness climbs generation-over-generation.

---

<br>

## <a name="performance"></a>8. Expected Performance Characteristics

### 8.1 Theoretical Performance Metrics

Based on our architecture, we can project the following performance characteristics for a full evolutionary campaign:

| Metric | Projected Value |
|--------|----------------|
| **Total population** | 200,000 payloads/generation |
| **Track 1 (core-mxss)** | 160,000 payloads (~10 min/generation) |
| **Track 2 (hook-bypass)** | 30,000 payloads (~1.5 hours/generation) |
| **Track 3 (integration)** | 10,000 payloads (~45 min/generation) |
| **Worker threads** | 14 parallel JSDOM instances |
| **Evaluation rate** | ~335/sec (Track 1), ~4.5/sec (Track 2) |
| **Memory footprint** | ~12-16GB RAM |
| **Generation time** | ~2.5 hours (bottlenecked by serial evaluation) |

### 8.2 Performance Bottlenecks and Trade-offs

**Track 1 (core-mxss)**: Parallelized with 14 worker threads achieving ~335 evals/sec. This represents 80% of the search space and completes rapidly (~10 minutes for 160k payloads).

**Track 2 (hook-bypass)**: Serial evaluation on main thread at ~4.5 evals/sec due to complex hook manipulation. Each payload requires 6 DOMPurify sanitization cycles with hook add/remove operations. This creates the primary bottleneck (~1.5 hours for 30k payloads).

**Track 3 (integration)**: Serial evaluation but smaller population (10k payloads, ~45 minutes).

**Optimization potential**: Hook-bypass and integration tracks could be parallelized, but they represent only 20% of the evolutionary effort. The computational investment may not justify the complexity, as Track 1 drives the core evolutionary process.

### 8.3 Key Metrics to Monitor During Execution

1. **Max fitness trajectory**: Whether high-fitness payloads (>0.7) emerge, indicating dangerous content surviving sanitization
2. **Population diversity**: Whether the algorithm explores the space broadly or converges prematurely
3. **Structural pattern dominance**: Which wrapper families (`<form><math>`, SVG, table-based) prove most effective
4. **Null byte effectiveness**: Whether evolutionary exploration of the 6,841 identified critical positions yields parser differentials
5. **Cross-namespace patterns**: Whether SVG+MathML confusion produces high-fitness payloads

### 8.4 Monitoring Infrastructure

The system includes real-time monitoring capabilities:

**Dashboard visualization**: Web-based interface with auto-refresh showing:
- Generation progress across all three tracks
- Current fitness statistics and diversity metrics
- Evaluation rate and resource utilization

**Phylogenetic tree viewer**: Canvas-rendered visualization showing:
- Payload lineages across generations
- Color-coded wrapper families (form+math, SVG, table-based)
- Interactive fitness breakdown on hover

**CLI monitoring**: JSON-based status files and structured logging for programmatic access

---

<br>

## <a name="outcomes"></a>9. Research Outcomes and Future Directions

### 9.1 Expected Outcomes and Success Criteria

A complete evolutionary campaign targeting DOMPurify represents substantial computational investment (estimated 1-5 days for convergence, depending on fitness landscape). We define success across multiple tiers:

**Tier 1: Core CVE Discovery**
- Zero-day bypass in DOMPurify's core sanitization logic
- Works against default configuration with no application-level errors
- Industry-wide impact affecting 30M+ weekly downloads
- CVE assignment and responsible disclosure
- Significant bug bounties across multiple platforms

**Tier 2: Hook/Configuration Bypasses**
- Bypasses in common application-level hook patterns
- Platform-specific but still valuable for bug bounty programs
- Validates that evolutionary approach can discover known vulnerability classes

**Tier 3: Integration Vulnerabilities**
- Post-sanitization processing bugs
- Demonstrates methodology effectiveness even without library-level bugs

**Tier 4: Negative Results**
- Systematic exploration of 10B+ payload combinations without XSS
- Strong evidence that DOMPurify is hardened against tested attack vectors
- Valuable for defensive validation and security confidence
- Publication of negative results advances the field

### 9.2 Vulnerability Disclosure Process

Upon discovery of a potential bypass (fitness = 1.0):

1. **Immediate halt and validation**: Stop campaign, capture full payload and lineage
2. **Cross-browser confirmation**: Test in Chrome, Firefox, Safari using Puppeteer headful mode
3. **Version bisection**: Determine affected DOMPurify versions via git bisect
4. **Minimal POC development**: Create reproducible proof-of-concept
5. **Responsible disclosure**: Private notification to DOMPurify maintainers (Cure53)
6. **CVE assignment**: Request CVE identifier from MITRE
7. **Coordinated release**: Public disclosure after patch availability
8. **Bug bounty submissions**: HackerOne, GitHub Security Lab, platform-specific programs

### 9.3 Future Research Directions

**Methodology extensions**:

1. **Adaptive rotor selection**: Bias mutation operators based on fitness feedback from previous generations
2. **Reinforcement learning guidance**: Train models to predict which feature combinations yield high fitness
3. **Multi-objective optimization**: Simultaneously optimize for multiple fitness dimensions rather than weighted sum
4. **Population sizing studies**: Determine optimal population size vs diversity trade-offs

**Target expansion**:

1. **Alternative sanitizers**: Bleach (Python), sanitize-html (Node.js), jsoup (Java), Ruby Sanitize
2. **Browser parser fuzzing**: Target HTML parser implementations directly (Chrome, Firefox, Safari differentials)
3. **WAF bypass evolution**: Evolve payloads against ModSecurity, Cloudflare WAF, AWS WAF
4. **Template injection**: Jinja2, Handlebars, ERB, Twig server-side template engines
5. **CSP bypass discovery**: Evolve payloads that work within strict Content Security Policies

**Open research questions**:

- What is the optimal balance between exploration (mutation rate) and exploitation (elitism)?
- Can semantic understanding of HTML parsing improve mutation operator design?
- How does fitness landscape topology affect convergence rates?
- Can adversarial training improve sanitizer robustness against evolutionary attacks?

### 9.4 Broader Implications

This research demonstrates that **vulnerability discovery can be formulated as an optimization problem** rather than random testing. The evolutionary approach provides:

- **Gradient-based search**: Partial successes guide exploration toward complete bypasses
- **Lineage tracking**: Understanding which attack patterns combine effectively
- **Systematic coverage**: Combinatorial explosion explored intelligently, not exhaustively
- **Reproducibility**: Methodology can be applied to any input-filtering system

The negative result (no bypass found) is as valuable as positive discovery—it provides quantitative evidence of sanitizer robustness under systematic evolutionary pressure.

---

<br>

## 10. Conclusion

This paper presents a novel methodology for systematic XSS bypass discovery using evolutionary algorithms. Our approach targeting DOMPurify represents a significant departure from traditional fuzzing:

- **200,000 payloads/generation** across three distinct attack tracks
- **Up to 50,000 generations** (10B+ evaluations) with early stopping criteria
- **Multi-dimensional fitness functions** capturing partial success gradients
- **6,841 null byte positions** identified in prior research, explored via 20+ targeted mutation operators
- **5-rotor mutation cascades** based on established XSS research (Heyes, GERVOT, Bentkowski, Heiderich)

The goal is ambitious: **discover zero-day CVEs in DOMPurify's core sanitization logic** through systematic evolutionary exploration.

### Key Innovation: Gradient-Based Vulnerability Discovery

Traditional fuzzing treats bypass attempts as binary (success/failure). Our evolutionary approach recognizes that vulnerability discovery has structure:

- Payloads that partially survive sanitization contain valuable information
- Structural mutations (`<form><math>` nesting) indicate parser edge cases
- Dangerous tag survival signals weakened filtering
- Attribute preservation shows incomplete sanitization
- Null byte positioning reveals parser differentials

By breeding from these partial successes, evolution climbs the fitness gradient toward complete bypasses.

### Research Value Regardless of Outcome

A complete campaign produces valuable results whether or not XSS is discovered:

**Positive result**: CVE discovery advances offensive security, triggers patches, earns recognition

**Negative result**: Systematic exploration of 10B+ combinations provides quantitative evidence of sanitizer robustness

Both outcomes contribute to the security research community. Offensive discoveries drive improvements; defensive validation builds confidence in deployed systems.

### Broader Applicability

While this methodology targets DOMPurify specifically, the approach generalizes to any input-filtering security system:

- HTML/XSS sanitizers (Bleach, sanitize-html, jsoup)
- SQL injection filters
- Command injection protections
- Template engine sandboxes
- WAF rulesets

By framing vulnerability discovery as an optimization problem, evolutionary algorithms can systematically explore attack surfaces that are too vast for exhaustive testing yet too structured for pure randomness.

**The future of security testing is not random—it's evolutionary.**

---

<br>

## Appendix A: Key Code Snippets

### A.1 Core Fitness Evaluator

```typescript
export class CoreMXSSEvaluator {
  private purify: any;
  private div1: any;
  private div2: any;

  evaluate(payload: Payload): CoreMXSSFitness {
    const sanitized = this.purify.sanitize(payload.content);

    return {
      structural: this.measureStructural(payload.content, sanitized),
      dangerous_tags: this.detectDangerousTags(sanitized),
      attributes: this.measureAttributeSurvival(payload.content, sanitized),
      null_byte_position: this.analyzeNullBytePosition(payload.content, sanitized),
      reparse_delta: this.measureReparseDelta(sanitized),
      execution: this.detectExecutionPotential(sanitized),
     : this.calculateTotal(/* ... */)
    };
  }

  private detectExecutionPotential(sanitized: string): number {
    // Fast path: no HTML
    if (!/<[a-zA-Z][^>]*>/.test(sanitized)) return 0;

    // Fast path: no dangerous patterns
    if (!/on[a-z]+=|javascript:|<script/i.test(sanitized)) return 0;

    // Slow path: DOM verification
    this.divExec.innerHTML = sanitized;
    if (this.divExec.querySelector('[onerror], [onload], [ontoggle]')) {
      return 1.0;  // CONFIRMED XSS!
    }

    return 0;
  }
}
```

### A.2 Tournament Selection

```typescript
selectParents(targetSize: number, tournamentSize: number = 5): Payload[] {
  const parents: Payload[] = [];

  while (parents.length < targetSize) {
    // Pick 5 random individuals
    const tournament = randomSample(this.population, tournamentSize);

    // Select the fittest
    const winner = maxBy(tournament, p => p.fitness.total);
    parents.push(winner);
  }

  return parents;
}
```

### A.3 Crossover (Feature Recombination)

```typescript
export function crossover(parent1: Payload, parent2: Payload): Payload {
  const features1 = extractFeatures(parent1);  // { wrapper, tag, event, ... }
  const features2 = extractFeatures(parent2);

  // Take best feature from each dimension
  const child = {
    wrapper: parent1.fitness.structural > parent2.fitness.structural
      ? features1.wrapper : features2.wrapper,
    tag: parent1.fitness.dangerous_tags > parent2.fitness.dangerous_tags
      ? features1.tag : features2.tag,
    event: parent1.fitness.attributes > parent2.fitness.attributes
      ? features1.event : features2.event
  };

  return reconstructPayload(child);
}
```

---

<br>

## Appendix B: Resources & References

### Research Papers
- Heyes, Gareth. "Mutation XSS (mXSS) research" (2013-2024)
- GERVOT, Kévin (mizu.re). "DOMPurify Bypass Collection" (2023-2025)
- Bentkowski, Michał. "DOMPurify mXSS Bypass Research" (2019-2024)
- Heiderich, Mario (Cure53). "mXSS Attacks" (2013)

### Tools
- **DOMPurify**: https://github.com/cure53/DOMPurify
- **[Enigma XSS Tool](/blog/enigma-xss-engine/)**: Autonomous XSS detection engine built on the 5-rotor methodology
- **Evolutionary Fuzzer**: Implementation will be open-sourced upon completion of research

### CVEs Referenced
- **CVE-2025-26791**: DOMPurify 3.2.3 template literal regex bypass (Jan 2025)
- **CVE-2024-45801**: DOMPurify namespace confusion (Sep 2024)
- **CVE-2023-48219**: TinyMCE + DOMPurify post-processing (Dec 2023)
- **CVE-2023-51467**: DOMPurify parser differential (Dec 2023)
- **CVE-2020-11022**: jQuery ≤3.4.1 nested tag vulnerability

---

**Paper Type**: Methodology and architecture description
**Implementation**: TypeScript/Node.js evolutionary fuzzing system
**Contact**: paul@trace37.com
**Code Release**: Implementation will be open-sourced upon completion of initial research

---

*"Evolution doesn't care about elegant solutions. It cares about what works."*

---

<br>

## Acknowledgments

This research builds upon foundational work by:
- **Gareth Heyes**: Systematic XSS exploration research that inspired our 5-rotor methodology
- **Kévin GERVOT (mizu.re)**: Comprehensive DOMPurify bypass cataloging and vulnerability research
- **Michał Bentkowski**: Multiple DOMPurify mXSS bypass discoveries including MathML namespace confusion
- **Mario Heiderich (Cure53)**: Original mXSS research and DOMPurify development
- **The security research community**: For continuous offensive/defensive advancement

---

*This research is part of the [Trace37 Labs](https://labs.trace37.com) security research program.*
