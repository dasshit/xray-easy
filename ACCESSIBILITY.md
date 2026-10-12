# Accessibility

Xray-easy aims to make its web control panel and project documentation usable
by people with different access needs. Accessibility is an ongoing effort; this
document describes the current status and how to report barriers.

## Current status

The web app's lint configuration includes static accessibility rules for Vue
components. Run them from the `web/` directory with:

```sh
npm run lint
```

These checks catch some code-level issues, but they do not replace keyboard,
screen-reader, visual, or usability testing. The project has not completed an
independent accessibility audit and does not claim conformance with a specific
WCAG level. A comprehensive list of known barriers is not yet available.

## Reporting an accessibility barrier

Please [open an issue](https://github.com/dasshit/xray-easy/issues/new/choose)
and select the **Bug report** template. Describe what you were trying to do,
what happened, and what you expected. When relevant, include your browser and
operating system, whether you were using a keyboard, and the assistive
technology and version involved. You do not need to share personal or medical
information.

Do not include passwords, access tokens, private keys, public server addresses,
or real user data. Redact this information from logs and screenshots.

## Guidance for contributors

When changing the web interface, contributors should:

- Prefer native semantic HTML and provide accessible names for controls and
  labels for form fields.
- Keep interactive features usable with a keyboard and make focus visible.
- Use headings and status messages that work with assistive technology.
- Avoid relying on color alone to communicate meaning and preserve readable
  text at enlarged sizes.
- Check the relevant interaction with a keyboard and run the web lint checks.

Please describe accessibility considerations in a pull request when a change
affects user-facing behavior or layout.
