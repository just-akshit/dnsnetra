---
name: DNSNetra
description: On-prem DNS telemetry and live threat intelligence in one analyst dossier.
colors:
  canvas: "oklch(1 0 0)"
  surface: "oklch(1 0 0)"
  chrome: "oklch(0.985 0 0)"
  chrome-active: "oklch(0.97 0 0)"
  ink: "oklch(0.145 0 0)"
  ink-muted: "oklch(0.556 0 0)"
  line: "oklch(0.922 0 0)"
  action: "oklch(0.205 0 0)"
  action-ink: "oklch(0.985 0 0)"
  focus: "oklch(0.708 0 0)"
  danger: "oklch(0.577 0.245 27.325)"
  verdict-clean: "oklch(0.508 0.118 165.612)"
  verdict-review: "oklch(0.555 0.163 48.998)"
  verdict-malicious: "oklch(0.514 0.222 16.935)"
  auth-canvas: "oklch(0.955 0.005 100)"
  auth-panel: "oklch(0.99 0.002 250)"
  auth-ink: "oklch(0.2 0.02 255)"
  auth-muted: "oklch(0.46 0.02 255)"
  auth-line: "oklch(0.87 0.008 255)"
  auth-accent: "oklch(0.45 0.1 215)"
  auth-danger: "oklch(0.5 0.17 25)"
typography:
  display:
    fontFamily: "DM Sans, Geist, system-ui, sans-serif"
    fontSize: "2.125rem"
    fontWeight: 700
    lineHeight: 1
    letterSpacing: "-0.03em"
  headline:
    fontFamily: "Geist, ui-sans-serif, system-ui, sans-serif"
    fontSize: "1rem"
    fontWeight: 600
    lineHeight: 1.375
    letterSpacing: "-0.01em"
  title:
    fontFamily: "Geist, ui-sans-serif, system-ui, sans-serif"
    fontSize: "1rem"
    fontWeight: 500
    lineHeight: 1.375
  body:
    fontFamily: "Geist, ui-sans-serif, system-ui, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 400
    lineHeight: 1.5
  label:
    fontFamily: "Geist, ui-sans-serif, system-ui, sans-serif"
    fontSize: "0.6875rem"
    fontWeight: 500
    lineHeight: 1.2
    letterSpacing: "0.05em"
  mono:
    fontFamily: "Geist Mono, ui-monospace, SFMono-Regular, monospace"
    fontSize: "0.75rem"
    fontWeight: 400
    lineHeight: 1.4
  micro:
    fontFamily: "Geist Mono, ui-monospace, SFMono-Regular, monospace"
    fontSize: "0.625rem"
    fontWeight: 400
    lineHeight: 1.2
    letterSpacing: "0.05em"
  auth-body:
    fontFamily: "Geist, ui-sans-serif, system-ui, sans-serif"
    fontSize: "0.9375rem"
    fontWeight: 400
    lineHeight: 1.5
rounded:
  xs: "0.25rem"
  sm: "0.375rem"
  md: "0.5rem"
  lg: "0.625rem"
  xl: "0.875rem"
  2xl: "1.125rem"
  3xl: "1.375rem"
  4xl: "1.625rem"
  auth: "0.875rem"
  auth-card: "2rem"
spacing:
  1: "0.25rem"
  1_5: "0.375rem"
  2: "0.5rem"
  2_5: "0.625rem"
  3: "0.75rem"
  4: "1rem"
  6: "1.5rem"
  8: "2rem"
components:
  button-primary:
    backgroundColor: "{colors.action}"
    textColor: "{colors.action-ink}"
    rounded: "{rounded.lg}"
    height: "2rem"
    padding: "0 0.625rem"
    typography: "{typography.body}"
  button-primary-hover:
    backgroundColor: "oklch(0.205 0 0 / 80%)"
    textColor: "{colors.action-ink}"
  button-outline:
    backgroundColor: "{colors.canvas}"
    textColor: "{colors.ink}"
    rounded: "{rounded.lg}"
    height: "2rem"
    padding: "0 0.625rem"
  button-ghost:
    backgroundColor: "transparent"
    textColor: "{colors.ink}"
    rounded: "{rounded.lg}"
    height: "2rem"
    padding: "0 0.625rem"
  button-destructive:
    backgroundColor: "oklch(0.577 0.245 27.325 / 10%)"
    textColor: "{colors.danger}"
    rounded: "{rounded.lg}"
    height: "2rem"
    padding: "0 0.625rem"
  input-default:
    backgroundColor: "transparent"
    textColor: "{colors.ink}"
    rounded: "{rounded.lg}"
    height: "2rem"
    padding: "0 0.625rem"
  badge-verdict:
    backgroundColor: "oklch(0.645 0.246 16.439 / 10%)"
    textColor: "{colors.verdict-malicious}"
    rounded: "{rounded.4xl}"
    height: "1.25rem"
    padding: "0 0.5rem"
  card-default:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.xl}"
    padding: "1rem"
  nav-item:
    backgroundColor: "transparent"
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
    height: "2rem"
    padding: "0 0.5rem"
  nav-item-active:
    backgroundColor: "{colors.chrome-active}"
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
  auth-submit:
    backgroundColor: "{colors.auth-ink}"
    textColor: "oklch(1 0 0)"
    rounded: "{rounded.auth}"
    height: "2.75rem"
---

# Design System: DNSNetra

## Overview

**Creative North Star: "The Instrument Panel"**

DNSNetra reads as a calibrated instrument, not a marketing surface. The chrome is achromatic graphite and paper white; the interface earns trust by being quiet, dense, and exact. Every pixel that isn't text is either a hairline, a tonal step, or a semantic verdict color. When something turns rose or amber, it is because the network did something an analyst must act on.

The system is built for long triage sessions on a self-hosted dashboard: compact 28–32px controls, 14px body copy, 11px uppercase labels, and Geist Mono for anything a machine produced — domains, IPs, counts, timestamps, ports, hashes. Density is the feature. A card is a panel, a table row is a reading, and the sidebar is a rail. Nothing floats for decoration; shadows appear only when a surface genuinely overlays another (dialog, drawer, popover, tooltip).

The one deliberate departure is the authentication surface. Login, signup, and password flows use a separate light-only palette — warm paper, an off-white panel, a deep institutional teal accent, and DM Sans for the wordmark. It is the front door of the building, not the operations floor. Do not import the auth teal into the dashboard chrome, and do not bring dashboard verdict colors into auth.

**Key Characteristics:**
- Achromatic dashboard chrome; color is reserved for state and verdict.
- Flat surfaces separated by 1px hairlines and tonal steps, not soft drop shadows.
- Operational density: h-7/h-8 controls, 0.625rem base radius, 4/8/12/16 spacing rhythm.
- Machine data in Geist Mono; prose and UI labels in the sans stack.
- Full light/dark parity in the dashboard; auth is always light.
- A single teal accent exists only on the auth surface.

## Colors

A near-monochrome instrument palette, with three semantic verdict hues and one isolated auth accent. Light and dark modes are both first-class; the frontmatter records the light canonical values and the dark overrides are listed per token below.

### Primary
- **Control Graphite** (`oklch(0.205 0 0)`): The primary action fill — default buttons, the shield mark tile, selected emphasis. It inverts to `oklch(0.922 0 0)` in dark mode with `oklch(0.205 0 0)` text, so "primary" always means maximum contrast, never a brand hue.

### Neutral
- **Clean White** (`oklch(1 0 0)`): Page canvas and default surface in light mode. Dark mode canvas is `oklch(0.145 0 0)`.
- **Panel White** (`oklch(1 0 0)`): Cards, popovers, dialogs. Dark mode is `oklch(0.205 0 0)`, one tonal step above the canvas.
- **Rail Off-White** (`oklch(0.985 0 0)`): Sidebar chrome. Dark mode is `oklch(0.205 0 0)`.
- **Rail Hover** (`oklch(0.97 0 0)`): Sidebar accent, muted blocks, secondary buttons, hovered rows. Dark mode is `oklch(0.269 0 0)`.
- **Terminal Ink** (`oklch(0.145 0 0)`): Primary text and icon color. Dark mode is `oklch(0.985 0 0)`.
- **Muted Graphite** (`oklch(0.556 0 0)`): Secondary text, metadata, placeholders, table headers. Dark mode is `oklch(0.708 0 0)`.
- **Hairline Gray** (`oklch(0.922 0 0)`): Borders, dividers, table rules, input strokes. In dark mode it becomes translucent white at 10% (`oklch(1 0 0 / 10%)`) so rules sit on the surface instead of cutting it.
- **Focus Gray** (`oklch(0.708 0 0)`): Focus rings and the focus-visible border. Dark mode is `oklch(0.556 0 0)`.

### Semantic Status
- **Verified Green** (`oklch(0.508 0.118 165.612)`): Clean, benign, active, done. Rendered as `text-emerald-700` on `bg-emerald-500/10` with a `border-emerald-600/25` edge; dark mode text is `emerald-400`.
- **Attention Amber** (`oklch(0.555 0.163 48.998)`): Suspicious, review needed, in process, flagged. `text-amber-700` on `bg-amber-500/10` with `border-amber-600/30`; dark mode text is `amber-400`.
- **Threat Rose** (`oklch(0.514 0.222 16.935)`): Malicious, blocked, threat, blacklisted. `text-rose-700` on `bg-rose-500/10` with `border-rose-600/30`; dark mode text is `rose-400`.
- **Signal Red** (`oklch(0.577 0.245 27.325)`): Destructive UI only — invalid input, destructive actions, destructive badges. Dark mode is `oklch(0.704 0.191 22.216)`. Not a verdict color.

### Auth Palette (light only)
- **Institutional Teal** (`oklch(0.45 0.1 215)`): The auth accent — focus rings, link hover, submit-button hover, caret, selection tint.
- **Warm Paper** (`oklch(0.955 0.005 100)`): Auth page background and the narrow-screen visual strip.
- **Auth Panel** (`oklch(0.99 0.002 250)`): The form panel inside the split card.
- **Auth Ink** (`oklch(0.2 0.02 255)`), **Auth Muted** (`oklch(0.46 0.02 255)`), **Auth Line** (`oklch(0.87 0.008 255)`), **Auth Danger** (`oklch(0.5 0.17 25)`).

### Named Rules
**The Signal-Only Color Rule.** In the dashboard, a non-neutral hue means a verdict or an error. If a color is not communicating malicious/suspicious/clean/danger, it is decoration and does not belong.

**The One Teal Rule.** `oklch(0.45 0.1 215)` exists only inside `.auth-theme`. It is never a dashboard accent, link color, or nav highlight.

## Typography

**Display Font:** DM Sans (with Geist and system-ui fallbacks) — auth wordmark only.
**Body Font:** Geist (with ui-sans-serif and system-ui fallbacks).
**Label/Mono Font:** Geist Mono for all machine-produced values.

**Character:** A precise, almost clinical pairing. Geist keeps dense tables legible at 14px; Geist Mono gives domains, IPs, counts, and timestamps the fixed-width alignment of a terminal readout. DM Sans appears exactly once — the auth wordmark — where its rounded geometry signals "front door" rather than "console."

**Implementation note:** Geist is loaded via `next/font` and exposed as `--font-geist-sans`, but `globals.css` currently defines `--font-sans: var(--font-sans)` (self-referential), so `font-sans` does not resolve to Geist and body copy falls back to the platform default. Bind `--font-sans` to `var(--font-geist-sans)` as a fix; do not hard-code a new family.

### Hierarchy
- **Display** (700, 2.125rem/2.35rem responsive, line-height 1, tracking -0.03em): Auth wordmark only.
- **Headline** (600, 1rem, line-height 1.375, tracking -0.01em): Page titles in the 3rem header; entity names on dossier pages.
- **Title** (500, 1rem, line-height 1.375): Card titles. Section titles inside panels are often 0.75rem semibold uppercase with wide tracking instead.
- **Body** (400, 0.875rem, line-height 1.5): Default UI and table text. Tables drop to 0.8rem for secondary cells; prose caps around 70ch.
- **Label** (500, 0.6875rem, tracking 0.05em, uppercase): Column eyebrows, card-section labels, overline metadata. Never used for sentences.
- **Mono** (400, 0.75rem, line-height 1.4): Domains, IPs, ports, counts, timestamps, provider names, keyboard hints. Numeric stat values step up to 1.125rem semibold.
- **Micro** (400, 0.625rem, tracking 0.05em): The smallest mono tier — badge metadata, provider badges, and inline status timestamps.
- **Auth Body** (400, 0.9375rem, line-height 1.5): The auth surface's field, label, and button text; one step larger than dashboard body.

### Named Rules
**The Mono-for-Machine Rule.** If a value came from the network or a provider, set it in Geist Mono. If a human wrote it as prose, use the sans stack. Mixed runs keep the machine half in mono.

**The Eyebrow Rule.** Uppercase 11px labels are navigation aids, not emphasis. One per panel section, muted color, wide tracking. Do not uppercase body sentences.

## Layout

The dashboard is a **sidebar-inset shell**. A fixed sidebar (16rem expanded, 3rem icon rail when collapsed, 18rem as a mobile sheet) sits on the Rail Off-White chrome; the main region is an inset panel offset by 0.5rem, rounded at 0.875rem, with a `shadow-sm` lift so it reads as a sheet on the rail. A 3rem header (`--header-height: calc(var(--spacing) * 12)`) spans the inset with a bottom hairline and holds the page title, the centered global search, and the theme toggle.

Content uses a 4/8/12/16 rhythm: `p-4 lg:p-6` page padding, `gap-6` between major blocks, `gap-4` between cards, `p-4` inside cards. Stat rows are `grid-cols-2 md:grid-cols-4`; dossier pages stack a profile header, a 4-up stat grid, then full-width evidence panels. Tables are the primary reading surface: 12px horizontal cell padding, hairline row rules, muted uppercase headers, and no zebra striping.

The shell is responsive by subtraction, not rearrangement: below `sm` the search trigger becomes an icon, below `md` the inset margin collapses, below `lg` multi-column grids fall to two or one column, and below `sm` the sidebar becomes a sheet. The auth surface is a centered split card capped at 1260px (1.08fr visual / 1fr form) with a 24rem form column; below `lg` it becomes a single column: wordmark, form, then a small visual strip.

**Breakpoints:** 640px `sm`, 768px `md`, 1024px `lg`, 1280px `xl`, 1536px `2xl`.

### Named Rules
**The Inset Rule.** The app is a sheet on a rail, not a border-to-border canvas. Keep the sidebar chrome, the 0.5rem inset, and the rounded main panel together; don't flatten the shell into a plain top-nav layout.

**The Two-Padding Rule.** Page gutters are 16px on mobile and 24px from `lg` up. Card padding stays 16px (12px for `size="sm"`). Don't invent intermediate steps.

## Elevation & Depth

**Flat by default, lifted only when overlapping.** The dashboard has no ambient shadows: cards separate from the canvas with a 1px `ring-foreground/10`, the sidebar inset uses a single `shadow-sm`, and everything else is flat. Shadows are reserved for surfaces that genuinely float above the page — dialogs, popovers, tooltips, menus, drawers — where the shadow is structural information ("this is on top"), not decoration. Dark mode replaces shadow contrast with tonal steps and translucent white hairlines.

### Shadow Vocabulary
- **Inset Lift** (`box-shadow: 0 1px 3px 0 rgb(0 0 0 / 0.1), 0 1px 2px -1px rgb(0 0 0 / 0.1)`): The sidebar-inset main panel at `md` and up.
- **Auth Card** (`box-shadow: 0 1px 2px 0 rgb(0 0 0 / 0.05)`): The auth split card only.
- **Overlay** (`box-shadow: 0 25px 50px -12px rgb(0 0 0 / 0.25)`): Dialogs, which also sit on `bg-black/60` with `backdrop-blur-xs`.
- **Floating Panel** (`box-shadow: 0 20px 25px -5px rgb(0 0 0 / 0.1), 0 8px 10px -6px rgb(0 0 0 / 0.1)`): Chart tooltips and elevated popovers.
- **Active Ring** (`box-shadow: 0 0 0 1px var(--sidebar-border)`): The raised state of a sidebar menu action; it reads as a 1px outline, not a glow.

### Named Rules
**The Flat Panel Rule.** If two surfaces are side by side, separate them with a hairline or a tonal step. A shadow means one surface is above another.

## Shapes

The form language is **soft-cornered rectangles**. The base radius is 0.625rem (10px); the scale multiplies it: `xs` 4px (keycaps only), `sm` 6px, `md` 8px, `lg` 10px, `xl` 14px, `2xl` 18px, `3xl` 22px, `4xl` 26px. Buttons and inputs use `lg`; cards and the inset panel use `xl`; sidebar rows use `md`; badges are full pills at `4xl` (26px).

Strokes are always 1px and always hairline: `border` on inputs and outlined controls, `ring-1 ring-foreground/10` on cards, `ring-sidebar-border` on sidebar surfaces. No heavy borders, no double strokes, no clipping beyond `overflow-hidden` on cards and the pill shape on badges. The auth surface bends the same language upward: 14px controls, a 32px outer card, and a 1.6rem inner panel.

### Named Rules
**The Hairline Rule.** One pixel is the only stroke weight in the system. If a boundary needs more emphasis than that, change the surface tone, not the border width.

## Components

### Buttons
- **Shape:** Soft 10px radius (`rounded-lg`), 1px transparent border, 32px default height. Sizes step to 24/28/36px (`xs`/`sm`/`lg`) and 32px square icons.
- **Primary:** Control Graphite fill with near-white text; hover drops the fill to 80% opacity so the surface shows through. No gradient, no accent hue.
- **Hover / Focus:** `transition-all` at 150ms; focus-visible adds a 3px `ring-ring/50` with a matching border; pointer press translates down 1px.
- **Secondary / Ghost / Outline:** Secondary uses the muted tonal step; outline uses the canvas with a hairline and a muted hover; ghost has no resting chrome and appears only on hover. Destructive is a 10% tinted fill with red text, never a solid red slab.
- **Disabled:** 50% opacity, pointer events off. `aria-invalid` shifts the border and ring to the danger hue.

### Badges / Verdict Chips
- **Style:** Pill (`rounded-4xl`, 26px), 20px high, 12px text, 8px horizontal padding, inline icon at 12px. Outline variant with a 25–30% tinted border and a 10% tinted fill.
- **State:** Verdict mapping is the contract: emerald for clean/benign/active/done, amber for suspicious/review-needed/in-process, rose for malicious/blocked/threat, muted for unknown/inactive. Never use these hues for anything else.

### Cards / Containers
- **Corner Style:** 14px (`rounded-xl`).
- **Background:** Panel White (dark: one step above canvas).
- **Shadow Strategy:** None at rest — a 1px `ring-foreground/10` does the separating. See Elevation & Depth.
- **Border:** None in addition to the ring.
- **Internal Padding:** 16px (`--card-spacing`), 12px for `size="sm"`; footers sit on `bg-muted/50` with a top hairline.

### Inputs / Fields
- **Style:** 32px high, 10px radius, transparent fill in light mode (translucent `input/30` in dark), hairline `border-input`, 10px horizontal padding.
- **Focus:** Border shifts to `ring` plus a 3px `ring-ring/50`.
- **Error / Disabled:** `aria-invalid` swaps border and ring to destructive; disabled uses `bg-input/50` (80% in dark) with 50% opacity.
- **Auth variant:** 44px high, 14px radius, white fill, 14px text, teal focus border with a 20% teal ring.

### Navigation
- **Style:** Sidebar groups with 11px uppercase muted section labels ("Overview", "Analysis", "System"), 14px menu rows at 8px radius, 16px icons, active state as a tonal `sidebar-accent` pill with medium weight. The brand block pairs a 32px graphite shield tile with the DNSNetra wordmark and a 12px "Threat Detection" subtitle.
- **Mobile:** The sidebar becomes an 18rem sheet; the header keeps a trigger and a vertical separator. Collapsed desktop mode is a 3rem icon rail with tooltips.

### Global Search (signature)
The global intelligence search is the product's front door inside the app: a 32px outlined trigger in the header (60/72/84px wide by breakpoint) that opens a command-palette dialog. Results group into Domains, Clients, and Queries, each row using the verdict chips above; a dedicated "lookup any domain or IP" row always appears for valid input, even with zero local telemetry. Partial backend failure shows one amber notice naming the failed categories while healthy results stay visible. The palette is 60vh max height, hairline-divided, with mono metadata and a keyboard footer (`↑↓` navigate, `↵` open, `ESC` close).

### Dialogs & Sheets
- **Style:** Centered, `max-w-xl`, `max-h-[85vh]`, 10px radius, Panel White, `shadow-2xl`, 150ms scale/fade. Backdrop is `bg-black/60` with `backdrop-blur-xs`. Sheets slide from the edge for mobile navigation.

### Auth Panel
A 1260px split card on Warm Paper: static artwork on the left, a centered 24rem form on the right, DM Sans wordmark, 44px fields, and one teal accent. Always light, regardless of the dashboard theme.

## Do's and Don'ts

### Do:
- **Do** keep the dashboard achromatic and let rose/amber/emerald appear only on verdicts, errors, and review states.
- **Do** separate adjacent surfaces with a 1px hairline or a tonal step before reaching for a shadow.
- **Do** use 28–32px controls and the 4/8/12/16 spacing rhythm; density is the product's advantage.
- **Do** set domains, IPs, counts, timestamps, and provider values in Geist Mono.
- **Do** preserve light/dark parity in the dashboard and verify both before shipping.
- **Do** surface partial failure and unavailability explicitly with the amber notice pattern.
- **Do** keep the auth surface on its own palette and radius; it is allowed to feel like a different room in the same building.

### Don't:
- **Don't** introduce a brand accent into dashboard chrome, links, active nav, or focus states.
- **Don't** use verdict hues for decoration, category coding, or chart series unrelated to a verdict.
- **Don't** add ambient drop shadows to cards, tables, or page sections.
- **Don't** exceed a 1px border, or stack a border and a ring on the same edge.
- **Don't** round cards to pills or square them off; the 10px base / 14px card / 26px pill scale is fixed.
- **Don't** bring the auth teal, DM Sans wordmark type, or warm paper background into the operations shell.
- **Don't** render a failed provider or empty category as "clean" or as a normal zero-result state.
