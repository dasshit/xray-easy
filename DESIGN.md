---
name: Xray-easy
description: Private VPN server control panel
colors:
  primary: "#315efb"
  primary-hover: "#244bd1"
  page-bg: "#f4f6fa"
  surface: "#ffffff"
  surface-muted: "#f4f6fa"
  text: "#172033"
  label: "#556176"
  muted: "#6b778c"
  border: "#e1e6ef"
  border-strong: "#cbd3df"
  focus: "#315efb26"
  error-surface: "#fff7f6"
  error-border: "#f2b8b5"
  error: "#b42318"
  danger-hover: "#8f1d16"
  success: "#1a9b58"
  status: "#a3adbb"
  warning: "#f0a000"
  warning-text: "#9a6500"
  warning-text-strong: "#b26b00"
  overlay: "#17203366"
  shadow: "#1720330d"
  modal-shadow: "#17203333"
  dark-page-bg: "#0f141f"
  dark-surface: "#151d2b"
  dark-surface-muted: "#202a3a"
  dark-text: "#edf2ff"
  dark-label: "#b9c3d4"
  dark-muted: "#a3afc3"
  dark-border: "#2b374a"
  dark-border-strong: "#43516a"
  dark-primary: "#849cff"
  dark-primary-hover: "#a3b5ff"
  dark-focus: "#849cff40"
  dark-error-surface: "#321c25"
  dark-error-border: "#763c4b"
  dark-error: "#ff9aa9"
  dark-danger-hover: "#ffb1bd"
  dark-success: "#61d994"
  dark-status: "#6c7890"
  dark-warning-text: "#f0bd58"
  dark-overlay: "#000000a8"
  dark-shadow: "#00000030"
  dark-modal-shadow: "#00000070"
typography:
  body:
    fontFamily: "Inter, ui-sans-serif, system-ui, sans-serif"
    fontSize: "16px"
    fontWeight: 400
  page-title:
    fontFamily: "Inter, ui-sans-serif, system-ui, sans-serif"
    fontSize: "1.55rem"
    fontWeight: 700
  section-title:
    fontFamily: "Inter, ui-sans-serif, system-ui, sans-serif"
    fontSize: "1.45rem"
    fontWeight: 700
  subsection-title:
    fontFamily: "Inter, ui-sans-serif, system-ui, sans-serif"
    fontSize: "1.2rem"
    fontWeight: 700
  eyebrow:
    fontFamily: "Inter, ui-sans-serif, system-ui, sans-serif"
    fontSize: "0.75rem"
    fontWeight: 700
    letterSpacing: "0.08em"
  label:
    fontFamily: "Inter, ui-sans-serif, system-ui, sans-serif"
    fontSize: "0.9rem"
    fontWeight: 400
  technical:
    fontFamily: "ui-monospace, monospace"
    fontSize: "0.72rem"
    fontWeight: 400
  action:
    fontFamily: "Inter, ui-sans-serif, system-ui, sans-serif"
    fontSize: "0.9rem"
    fontWeight: 650
rounded:
  control: "9px"
  compact: "10px"
  nested-card: "14px"
  dialog: "16px"
  card: "20px"
  pill: "999px"
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.page-bg}"
    typography: "{typography.action}"
    rounded: "{rounded.control}"
    padding: "10px 16px"
    height: "42px"
  button-secondary:
    backgroundColor: "transparent"
    textColor: "{colors.primary}"
    typography: "{typography.action}"
    rounded: "{rounded.control}"
    padding: "8px 12px"
  text-field:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
    padding: "10px 12px"
    height: "44px"
  navigation-tab:
    backgroundColor: "transparent"
    textColor: "{colors.muted}"
    rounded: "0px"
    padding: "13px 14px"
  status-badge:
    backgroundColor: "{colors.surface-muted}"
    textColor: "{colors.muted}"
    rounded: "{rounded.pill}"
    padding: "5px 9px"
  card:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.card}"
    padding: "30px"
  device-card:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.nested-card}"
    padding: "19px"
---

# Design System: Xray-easy

## Overview

**Creative North Star: "Private VPN Server panel"**

The interface is a calm, open control surface for one private VPN server. It favors clear labels, direct actions, and cool neutral space over dense enterprise-dashboard styling. The four-point brand mark is a small anchor in the header; the interface itself stays focused on the administrator's work.

Clear Blue marks primary actions, active navigation, and links. Light and dark themes keep the same role hierarchy while shifting the canvas, text, surfaces, and accent values together. Cards and borders group operational details without making every control compete for attention.

**Key Characteristics:**
- Calm and open, with compact, legible operational content.
- Clear Blue accents against cool, low-chroma surfaces.
- Layered panels with soft shadows and simple status treatments.

## Colors

The palette uses one direct blue accent with cool blue-gray neutrals. Light and dark themes preserve the semantic roles listed below; the frontmatter is the source of exact values.

### Primary
- **Clear Blue:** Primary buttons, active tab indicators, links, and focus borders. Its dark-theme counterpart is lighter so the same actions remain visible on dark surfaces.

**The One Accent Rule.** Keep Clear Blue as the interface's only saturated accent; reserve green, red, and amber for their status meanings.

### Neutral
- **Cool Mist:** The light page canvas and muted surfaces.
- **Paper:** The light content surface used for cards and fields.
- **Ink:** Main text; **Slate Label** and **Muted Slate** carry labels and secondary information.
- **Quiet Border** and **Strong Border:** Separate adjacent surfaces and define field boundaries without heavy rules.
- **Night Canvas**, **Night Surface**, and **Night Slate:** The dark-theme page, raised surfaces, and muted fills. **Moon Ink** and **Silver Slate** preserve text hierarchy in that theme.

### Status
- **Success Green:** Running, enabled, and positive states.
- **Error Red:** Destructive, failed, and invalid states, paired with a tinted surface and border.
- **Amber Warning:** Expiry and configuration warnings. Keep warning text legible on both theme surfaces.

## Typography

**Display Font:** Inter (with the system sans-serif stack). The interface has no separate display face.
**Body Font:** Inter, falling back through ui-sans-serif and system-ui.
**Label/Mono Font:** The body stack for labels; ui-monospace for IDs, fingerprints, recovery codes, and technical values.

**Character:** The type is compact and direct, with weight and color doing more work than decorative treatments. Labels remain readable beside precise network and security values.

### Hierarchy
- **Page title** (bold, 1.55rem): Setup and login form headings.
- **Section title** (bold, 1.45rem): The primary heading inside a panel.
- **Subsection title** (bold, 1.2rem): Card and modal headings.
- **Body** (regular, 16px): Default control and explanatory text.
- **Label** (regular, 0.9rem): Form labels.
- **Eyebrow** (bold, 0.75rem, 0.08em tracking, uppercase): Quiet section identifiers above a stronger heading.
- **Technical** (0.72rem monospace): Device IDs and compact technical metadata. Longer fingerprints and addresses wrap instead of forcing the layout wider.

## Layout

The app uses a centered workspace with a maximum width of 1120px. The desktop shell has 24px horizontal padding and 30px top padding; larger cards and sections use 20–30px internal padding. Repeated inner groups use tighter 8–18px gaps, with borders and muted fills separating related controls.

At 700px and below, the shell tightens to 12px side padding, cards reduce to 20px padding and a 12px radius, and two-column settings, security, file, and diagnostics layouts collapse to one column. At 480px and below, the theme label and server-status pill disappear from the header, profile delivery and modal actions stack vertically, and section-heading actions become full-width. The dashboard tabs scroll horizontally rather than wrapping.

## Elevation & Depth

Depth is layered. The main card and dashboard use soft shadows to lift the work surface; dialogs receive the strongest shadow above a dimmed overlay. Inner settings and security cards stay flat and use a one-pixel border and muted fills to show grouping. Device cards gain a restrained shadow and one-pixel lift on hover. Keep shadows broad and quiet so the interface remains calm.

**The Quiet Elevation Rule.** Keep the strongest shadows on the main work surface and dialogs; inner cards use borders and tonal fills.

## Shapes

Controls use gently rounded corners (9px), with small variations for compact panels (10px), nested cards (14px), and dialogs (16px). Main cards are rounder (20px) on desktop and tighten on small screens. Status and protocol badges use pill silhouettes. Fields and cards have thin borders; keyboard focus uses a clearly offset outline rather than relying on color alone.

## Components

### Buttons
- **Character:** Clear and functional, with one strong action style and quieter secondary actions.
- **Primary:** Blue fill, page-colored text, 10px by 16px padding, and a 42px minimum height. The label is semibold.
- **Secondary:** Transparent at rest with blue text and 8px by 12px padding. Keep hover and focus states distinct and readable against the active theme.
- **Danger:** Text-only for lower-emphasis destructive actions; filled red is reserved for destructive confirmation.
- **States:** Hover shifts the primary fill, active presses down by 1px, disabled controls fade, and keyboard focus receives a 3px outline with a 2px offset.

### Cards / Containers
- **Corner style:** Main cards use the larger card radius; nested settings and device cards use the nested-card radius.
- **Background:** White or dark raised surfaces for the main work areas; muted fills and borders group inner details.
- **Shadow strategy:** Use the soft card shadow for outer work surfaces and the stronger shadow for dialogs. Inner settings cards remain flat.
- **Internal padding:** Main cards use 30px on wide screens and 20px on small screens. Settings/security cards use 20px; device cards use 19px on wide screens and 16px on small screens.

### Inputs / Fields
- **Style:** Full-width surface fill, a 1px strong border, 9px corners, 10px by 12px padding, and a 44px minimum height.
- **Focus:** Change the border to Clear Blue and show the shared offset focus ring.
- **Read-only:** Use the muted surface to distinguish values supplied by deployment configuration.
- **Technical text:** Textareas can grow vertically; long credentials and machine values wrap instead of widening their container.

### Navigation
- **Style:** Horizontal tabs sit on a thin divider. Inactive tabs use muted text; the active tab uses Clear Blue and a 3px underline.
- **Responsive behavior:** Keep tabs on one line and allow horizontal scrolling on narrow screens.

### Status and Protocol Badges
- Use compact pill shapes with tinted neutral, success, warning, or error surfaces. Pair status color with readable text; do not make color the only state signal.

**The Visible State Rule.** Pair status color with text, and preserve a visible offset keyboard focus ring.

### Dialogs
- Center dialogs over a dimmed full-screen backdrop, keep them within the viewport height, and allow long content to scroll. The profile-delivery dialog may be wider on desktop and becomes a single column on small screens.

## Do's and Don'ts

### Do:
- **Do** use Clear Blue for the main action and active navigation state.
- **Do** keep light and dark themes aligned by semantic role.
- **Do** group controls with spacing, subtle borders, and muted surfaces before adding stronger shadows.
- **Do** preserve visible keyboard focus and pair status colors with text.
- **Do** let technical values wrap within their card or field.

### Don't:
- **Don't** add a second saturated accent without a product reason.
- **Don't** turn the panel into a dense enterprise dashboard; keep its groups open and easy to scan.
- **Don't** use heavy shadows on every nested card.
- **Don't** communicate enabled, disabled, warning, or error state through color alone.
