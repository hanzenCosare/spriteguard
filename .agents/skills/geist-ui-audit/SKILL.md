---
name: geist-ui-audit
description: Audit and polish web interfaces against Vercel Geist and Web Interface Guidelines (interactive selection states, microcopy casing, contrast, spacing, and keyboard/mobile ergonomics) while preserving the app's own brand identity.
---

# Geist UI/UX Micro-Polish Audit

When asked to audit or polish a frontend UI:

1. **Interactive Selection & Feedback States**
   - Every preset pill, filter tab, toggle, and segmented control MUST visibly distinguish its active item (`aria-pressed="true"` or `aria-selected="true"`, distinct border/fill contrast) and clear active preset styling if the user manually edits the bound inputs.
   - Every async button must show a disabled/loading state (`aria-busy="true"`) while in flight and never rely on hover/focus alone to show selection.

2. **Microcopy & Casing Consistency**
   - Use **Title Case** on all product buttons, tabs, and section headings (`Run Demo Audit`, `Approve Patch`, `Connect Repo`).
   - Use **sentence case** for helper descriptions and banners.
   - Replace ambiguous toggle labels (e.g., showing `"Dark"` when already in dark mode) with explicit state/action labels (`Switch to Light` or a clear icon + active mode).
   - Use real ellipsis characters (`…`) instead of `...` in loading and placeholder strings.

3. **Layout, Hairline Borders & Optical Alignment**
   - Draw each `1px` border once; separate distinct actions within the same card (such as custom code forms vs. URL inputs) with a clean hairline divider.
   - Keep `font-variant-numeric: tabular-nums` on all metrics, scores, counts, and timestamps.
   - Ensure concentric border radii (child radius <= parent radius) and >= `40px` touch targets on mobile.

4. **Preserve Brand Identity & Backend Contracts**
   - Keep the project's own color palette, logo mark, and API bindings intact. Never introduce mock data or alter backend logic during a UI polish pass.