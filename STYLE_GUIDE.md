# Professional Web Application Style Guide

This guide defines a professional, desktop-first interface system for complex product surfaces. It is intentionally content-agnostic: it governs structure, tone, density, visual language, and interaction behavior, not application-specific pages, entities, or workflows.

The target aesthetic is calm, operational, and trustworthy. Interfaces should feel precise, low-noise, auditable, and efficient under prolonged use.

## 1. Design posture

- Build for clarity before expressiveness.
- Prefer repeatable patterns over novelty.
- Support dense, serious work without feeling cramped.
- Make state, hierarchy, and consequence immediately legible.
- Treat destructive actions, warnings, and irreversible changes as first-class visual states.
- Favor discipline over decoration: alignment, spacing, and typography should carry most of the interface.

Avoid consumer-product styling, playful illustration, oversized card layouts, loud gradients, glossy effects, and heavy shadow stacks.

## 2. Product shape

Use a desktop-first, light-theme application shell with persistent navigation and a structured content workspace.

Recommended shell:

- fixed left navigation
- sticky page header
- optional local toolbar below the header
- main content area designed for dense inspection, configuration, and tabular work

Behavior rules:

- navigation should remain visible on desktop
- headers may stay sticky when they preserve context
- long datasets should scroll inside their own region when that prevents surrounding UI from being lost
- split-pane layouts are preferred when browsing and inspecting must happen together
- resizable panes are appropriate only when both panes carry sustained value

## 3. Information architecture

- One page should have one primary purpose.
- One region should have one primary action.
- Navigation labels must be short, literal, and stable.
- Group by user task and decision boundary, not by implementation detail.
- Advanced controls should appear through progressive disclosure, not visual overload.
- High-signal metadata such as state, timestamps, ownership, severity, or change history should surface early when relevant.
- Do not make users infer importance from placement alone; combine layout, typography, spacing, and contrast.

## 4. Visual language

The interface should be built from neutrals plus one restrained primary accent. Semantic colors are functional, not decorative.

Visual rules:

- most surfaces stay white or near-white
- contrast between adjacent surfaces should be subtle but explicit
- borders and dividers should do more work than shadows
- accent color should be used for action, focus, selection, and active state
- semantic colors should appear mainly in badges, inline signals, alerts, and validation
- large color fields should be rare
- radius should be modest and consistent
- elevation should communicate layering only

Avoid making entire sections visually loud just to signal importance. Importance should come from hierarchy and structure first.

## 5. Color system

Base palette:

- background: `#F6F8FB`
- navigation background: `#F3F5F8`
- surface: `#FFFFFF`
- subtle surface: `#F8FAFC`
- border: `#DCE3EC`
- divider: `#E7EDF3`

Text palette:

- primary text: `#0F172A`
- secondary text: `#475569`
- tertiary text: `#64748B`
- disabled text: `#94A3B8`

Accent palette:

- primary accent: `#2563EB`
- accent hover: `#1D4ED8`
- accent soft background: `#DBEAFE`

Semantic palette:

- success: `#15803D`
- warning: `#B45309`
- danger: `#B91C1C`
- info: `#0369A1`

Usage rules:

- never rely on color alone to communicate meaning
- do not place accent color on large structural surfaces
- semantic colors should generally appear with muted fills and stronger text
- disabled states should reduce emphasis without destroying legibility

## 6. Typography

Use one neutral sans-serif family for interface text and one monospace family for technical content.

Recommended stacks:

- UI: `Inter`, `SF Pro Text`, `Segoe UI`, sans-serif
- mono: `JetBrains Mono`, `SF Mono`, `Menlo`, monospace

Type scale:

- page title: `24 / 32`, weight `600`
- section title: `18 / 28`, weight `600`
- subsection title: `16 / 24`, weight `600`
- body: `14 / 20`, weight `400`
- secondary body: `13 / 18`, weight `400`
- label / caption: `12 / 16`, weight `500-600`
- monospace content: `12 / 18` or `13 / 20`

Typography rules:

- use sentence case for headings, labels, tabs, and actions
- reserve bold for hierarchy, not emphasis inside paragraphs
- keep long-form reading widths under control
- use monospace for tokens, code, paths, identifiers, timestamps, or aligned values when it improves scanning
- avoid more than four font sizes in one view

## 7. Spacing, sizing, and rhythm

Use an 8 px spacing grid with a compact, repeatable scale.

Preferred scale:

- `4`
- `8`
- `12`
- `16`
- `24`
- `32`
- `40`
- `48`

Layout defaults:

- sidebar width: `248-264 px`
- page padding: `24 px`
- page padding on large screens: `32 px`
- section spacing: `24 px`
- toolbar height: `48-56 px`
- page header height: `64-72 px`
- standard card or panel padding: `16 px`
- generous panel padding: `20 px`

Component sizing:

- compact controls: `32 px`
- standard controls: `40 px`
- default table row height: `44-48 px`
- compact table row height: `36 px`

Rhythm rules:

- use spacing to reveal structure, not to create softness
- keep related items visually tight
- increase separation only when meaning changes
- do not solve hierarchy with oversized padding

## 8. Borders, radius, and shadow

- default border: `1 px solid #DCE3EC`
- control radius: `8 px`
- panel radius: `10-12 px`
- modal or drawer radius: `12 px`

Shadow policy:

- cards should have either no shadow or a faint shadow only
- overlays may use one soft elevation layer
- avoid stacked, glassy, or floating shadow treatments

## 9. Component hierarchy

Use a limited component vocabulary and make differences meaningful.

Buttons:

- primary: filled accent, reserved for the main action in a local area
- secondary: neutral bordered action
- tertiary: text or ghost action
- danger: destructive action, visually distinct from safe actions

Rules:

- do not place multiple primary buttons in the same region
- dangerous actions must never be visually equivalent to safe actions
- action labels should begin with a verb

Inputs and forms:

- prefer explicit labels over placeholder-only inputs
- helper text belongs below the field
- group related controls into short, scannable sections
- prefer single-column forms unless side-by-side comparison materially improves comprehension
- use inline validation only when it is immediate and actionable
- preserve save visibility on long forms with a sticky footer or similar pattern when needed

Panels and cards:

- use panels to group related information or controls
- do not wrap every block in a card by default
- avoid nested cards inside cards
- dense content should stay dense; padding should clarify, not dilute

Tabs and segmented controls:

- tabs are for peer views
- segmented controls are for short, mutually exclusive view states
- keep tab counts low enough to scan without wrapping

Badges and statuses:

- statuses must include text
- muted fills and strong text contrast are preferred over saturated chips
- label sets should stay short and consistent across the product

## 10. Data-dense surfaces

The system should handle tables, lists, logs, inspectors, timelines, and forms without falling into visual noise.

Tables and lists:

- text aligns left, numeric values align right
- sticky headers are appropriate for long datasets
- sort state, filter state, loading, empty, and error states must be explicit
- row hover should be subtle
- avoid zebra striping unless it materially improves scan accuracy
- bulk actions should appear only when they are common and safe

Split views:

- use split views for browse-and-inspect flows
- preserve list filters, scroll position, and selection when opening details
- do not force full-page navigation for simple inspection tasks

Logs and code-like surfaces:

- use monospace
- preserve scanability with wrapping controls or horizontal scroll where needed
- timestamps and severity should be easy to parse
- actions such as copy, filter, and search should remain close to the content

## 11. Interaction model

- every interactive element must look interactive
- every mutation must produce visible feedback
- long-running operations should show progress, not generic loading
- partial failure must state what succeeded and what failed
- inline actions are acceptable only when they remain discoverable and safe
- confirmations should scale with risk
- high-risk operations may require explicit confirmation text when warranted
- preserve user context whenever possible during inspection and editing flows

Primary action placement:

- page-level primary actions belong in the top-right area of the page header
- secondary actions belong in toolbars or overflow menus
- frequent, safe row actions may appear inline

## 12. Accessibility and usability

- minimum text contrast for normal text: `4.5:1`
- all interactive elements require visible keyboard focus
- status and validation must not depend on color alone
- icon-only controls require accessible names and clear tooltips where appropriate
- hit targets should be at least `32 px`
- interfaces must remain usable at `200%` zoom
- semantic structure should be preserved for assistive technology
- keyboard navigation should work across navigation, tables, tabs, forms, overlays, and data viewers

Focus treatment:

- use a `2 px` accent focus ring with a soft outer halo
- focus must remain visible on both light and dark surfaces

## 13. Copy style

- use literal, operational language
- prefer direct verbs and precise nouns
- avoid hype, metaphor, and vague feature labels
- keep actions concise and specific
- make time, consequence, and state explicit when relevant
- error copy should explain the problem, likely impact, and next step

## 14. Motion

Motion should support orientation, not decoration.

- use short, consistent durations
- reserve animation for state change, layout transition, reveal, and confirmation
- avoid theatrical entrances or constant micro-motion
- ensure reduced-motion behavior is defined and respected

## 15. Session Transcripts

Session transcripts display the chronological record of interactions between users and agents. To maintain a scannable, calm aesthetic without overwhelming the user, the layout relies on progressive disclosure, clean structural lines, and distinct visual treatments for different types of content.

Overall layout and structure:
- represent the session as a vertical timeline or conversation thread
- rely on padding, borders, and subtle background shifts to group related items, reserving strong shadows or borders for primary content
- default to progressive disclosure: show high-level actions, summaries, and final answers immediately; collapse verbose details (such as long outputs or step-by-step reasoning) behind simple toggle elements (e.g., accordions or `details` blocks)

Reasoning and internal thoughts:
- present the agent's internal reasoning as distinct message blocks
- use a distinct, subtle background color to separate reasoning from user input and final outputs (e.g., a soft purple or indigo like `#F5F3FF` surface with `#4C1D95` text)
- keep reasoning text slightly de-emphasized compared to final answers, using the secondary body typography size (`13 / 18`) or an italicized treatment

Terminal and command outputs:
- display command execution and standard outputs as terminal-like snippets
- use a dark background (e.g., `#0F172A`) to strongly differentiate terminal environments from the rest of the light-themed application shell
- use the standard monospace font stack (`JetBrains Mono`, `SF Mono`, etc.)
- include distinct visual cues for the prompt line (e.g., `$`, `>`) versus the output lines
- apply a maximum height with internal scrolling for very long outputs to preserve page position and avoid breaking the primary layout flow

Metadata and density:
- keep metadata such as timestamps, execution duration, and exit codes logically grouped and clearly legible but de-emphasized (using secondary or tertiary text colors like `#475569` or `#64748B`)
- display badges for the success/failure states of commands (e.g., `Exit Code: 0` using the success semantic palette, `Exit Code: 1` using the danger palette)


## 15. Design tokens

Standardize tokens before introducing local values.

Minimum token set:

- color: background, surface, subtle surface, border, divider, text, accent, semantic states
- typography: family, size, weight, line-height
- spacing: scale, gaps, padding
- radius: small, medium, large
- elevation: none, low, medium
- motion: duration, easing, reduced-motion
- sizing: control heights, layout widths, breakpoints

Reference token block:

```css
:root {
  --bg: #F6F8FB;
  --sidebar-bg: #F3F5F8;
  --surface: #FFFFFF;
  --surface-subtle: #F8FAFC;
  --border: #DCE3EC;
  --divider: #E7EDF3;

  --text: #0F172A;
  --text-secondary: #475569;
  --text-tertiary: #64748B;
  --text-disabled: #94A3B8;

  --accent: #2563EB;
  --accent-hover: #1D4ED8;
  --accent-soft: #DBEAFE;

  --success: #15803D;
  --warning: #B45309;
  --danger: #B91C1C;
  --info: #0369A1;

  --radius-sm: 8px;
  --radius-md: 10px;
  --radius-lg: 12px;

  --space-1: 4px;
  --space-2: 8px;
  --space-3: 12px;
  --space-4: 16px;
  --space-6: 24px;
  --space-8: 32px;

  --shadow-sm: 0 1px 2px rgba(15, 23, 42, 0.04);
  --shadow-md: 0 8px 24px rgba(15, 23, 42, 0.08);
}
```

## 16. Do / don't

Do:

- keep the interface quiet and structured
- favor stable component patterns
- optimize for fast scanning and reliable interpretation
- separate safe, warning, and destructive states clearly
- support dense data without visual clutter
- use hierarchy, not decoration, to communicate importance

Don't:

- encode meaning in ornament
- default to oversized cards or soft consumer layouts
- hide critical actions in ambiguous menus
- overuse color, shadow, or radius
- create a new pattern for each screen
- let visual style outrun operational clarity
