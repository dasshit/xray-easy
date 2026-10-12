# Security Policy

## Supported versions

Security fixes are provided for the latest stable release. If you are using an
older release, update to the latest stable release before reporting an issue;
backports to older releases are not guaranteed.

## Reporting a vulnerability

Please do not report security vulnerabilities in public issues, pull requests,
discussions, or commit messages.

The preferred reporting channel is
[GitHub private vulnerability reporting](https://github.com/dasshit/xray-easy/security/advisories/new),
when it is available for this repository. If it is unavailable and you do not
have a private contact method for the maintainers, open an issue asking for
their preferred private reporting channel. Do not describe the suspected
vulnerability or name the affected component in that issue.

Include, when possible:

- The affected release, commit, component, and deployment configuration.
- The security impact and conditions needed to trigger it.
- Reproduction steps or a minimal proof of concept.
- Any known exploitation or planned public disclosure date.

Do not include passwords, access tokens, private keys, real user data, or other
secrets in a report. Share only the information needed to investigate the
issue.

## Response and disclosure

Maintainers aim to acknowledge reports within five business days. They will
investigate the report, keep the reporter informed as they assess it, and
coordinate disclosure when a fix or mitigation is available. Reporters should
allow maintainers a reasonable opportunity to investigate and prepare a fix
before public disclosure. The time needed to confirm and address an issue
depends on its severity, impact, and complexity.

When appropriate, a fix and security advisory will be published through GitHub
and included in release information. Reporter credit will be included only with
their consent. The project does not currently offer a paid bug bounty.

## Scope

This policy covers security vulnerabilities in this repository's code, its
official release process, and the container images published for this project.
Issues in third-party dependencies may also be reported here; maintainers may
coordinate with the relevant upstream project.
