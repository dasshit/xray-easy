# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

The primary user is an administrator who runs their own VPN server on a Linux VPS. They use Xray-easy to set up and maintain the server and to create, manage, and revoke connection profiles for client devices.

## Product Purpose

Xray-easy is a self-hosted Docker Compose application for setting up and operating a VPN server with Xray and optional AmneziaWG. It succeeds when an administrator can configure the server, manage device profiles, and handle diagnostics and maintenance from a private web panel without hand-editing Xray configuration files.

## Positioning

Xray-easy brings server setup, a private web control panel, and protocol-specific device profile management together for a single self-hosted server. Its panel manages an embedded Xray runtime and can also manage an optional AmneziaWG service.

## Operating Context

- The application is deployed on a Linux VPS with Docker Compose. The administrator connects from their own computer over SSH.
- The web panel listens on the VPS loopback interface and is intended to be reached through an SSH tunnel. Its port must not be exposed publicly.
- VPN client devices connect to the server's configured public Xray or AmneziaWG endpoints.
- The installer configures deployment-wide values and optional services; the panel manages protocol settings and individual device profiles.

## Capabilities and Constraints

- VLESS + REALITY is the default Xray profile. Optional Xray profiles include Hysteria 2, VMess + TLS, Shadowsocks 2022, and Trojan + TLS. AmneziaWG is an optional, separate service.
- Administrators can create and manage device profiles, deliver them as links, QR codes, or files where supported, view connection status and traffic, and set profile expiry.
- The panel includes administrator authentication, optional TOTP, service diagnostics, protocol settings, and backup and restore workflows.
- Optional protocols and services depend on their installation and server configuration. Profile formats, transport behavior, and security properties differ by protocol; product copy must describe those differences accurately.
- Connection profiles and backups contain credentials or keys and must be treated as sensitive. Backups are plaintext.
- The documented product scope is one administrator and one server.

## Brand Commitments

- Product name: Xray-easy.
- Existing identity assets are `web/public/favicon-light.svg`, `web/public/favicon-dark.svg`, and `docs/assets/xray-easy-banner.svg`.
- The README describes the product as a private VPN control panel for an administrator's own server.

## Evidence on Hand

The repository contains the running application, installer, README, protocol and operations documentation, and the identity assets listed above. It does not provide customer testimonials, adoption metrics, or independent product validation; future work must not invent them.

## Product Principles

- Keep administrative access private and reachable through SSH.
- Let administrators manage device-specific profiles through the panel instead of hand-editing Xray configuration.
- Explain optional services, protocol requirements, and protocol limitations accurately.
- Treat profiles, server keys, and backups as sensitive credentials.
- Keep setup and routine operation within the documented single-server scope.
