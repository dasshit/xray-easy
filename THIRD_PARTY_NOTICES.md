# Third-party notices

This file records third-party software used by the project, including software
linked into distributed binaries, the web application, build tools, and runtime
container packages. Project-authored code is licensed under GPL-3.0-or-later;
the GPLv3 text is in [`LICENSE`](LICENSE). Each third-party component remains
under its own upstream license; this file does not relicense third-party code.
Exact Go versions are recorded in the Go manifests and module checksums in the
`go.sum` files listed below. The npm lock file records the resolved versions
and license metadata for the web dependency tree.

## Components embedded in Go binaries

| Component | Version | License | Use |
| --- | --- | --- | --- |
| [Xray-core](https://github.com/XTLS/Xray-core) | `v1.260327.1-0.20260728075948-5ca6f4b7d4dc` | MPL-2.0 | Embedded in the `xray-runtime` binary. |
| [SagerNet sing](https://github.com/SagerNet/sing) | `v0.5.1` | GPL-3.0-or-later | Dependency used by Xray's Shadowsocks-2022 implementation. |
| [SagerNet sing-shadowsocks](https://github.com/SagerNet/sing-shadowsocks) | `v0.2.7` | GPL-3.0-or-later | Shadowsocks-2022 implementation linked into `xray-runtime`. |
| [juju/ratelimit](https://github.com/juju/ratelimit) | `v1.0.2` | LGPL-3.0 with Canonical's linking exception | Used by the Xray REALITY dependency; see its upstream license for the exception's terms. |
| [AmneziaWG-Go](https://github.com/amnezia-vpn/amneziawg-go) | `v3.1.20260828` | MIT | Optional AmneziaWG service; linked into `awg-service`. License text: [`third_party/licenses/AMNEZIAWG-GO-MIT-LICENSE`](third_party/licenses/AMNEZIAWG-GO-MIT-LICENSE). |
| [skip2/go-qrcode](https://github.com/skip2/go-qrcode) | `v0.0.0-20200617195104-da1b6568686e` | MIT | QR generation; source is vendored under `third_party/go-qrcode`. License text: [`third_party/go-qrcode/LICENSE`](third_party/go-qrcode/LICENSE). |
| [GORM](https://github.com/go-gorm/gorm) and [GORM SQLite driver](https://github.com/go-gorm/sqlite) | `v1.31.2`, `v1.6.0` | MIT | SQLite persistence in the control-plane application. |
| [mattn/go-sqlite3](https://github.com/mattn/go-sqlite3) | `v1.14.22` | MIT | Transitive dependency of the GORM SQLite dialect. |
| [modernc.org/sqlite](https://github.com/modernc-org/sqlite) | `v1.34.5` | BSD-3-Clause | Pure-Go SQLite driver used by the application. |
| [gRPC-Go](https://github.com/grpc/grpc-go) | `v1.76.0` / `v1.82.1` | Apache-2.0 | RPC transport in the application and embedded runtime. |
| [Protocol Buffers for Go](https://github.com/protocolbuffers/protobuf-go) | `v1.36.6` / `v1.36.11` | BSD-3-Clause | Protocol Buffer runtime. |
| [golang.org/x/crypto](https://go.googlesource.com/crypto), [x/sys](https://go.googlesource.com/sys), [x/net](https://go.googlesource.com/net), and [x/text](https://go.googlesource.com/text) | Versions vary by Go module | BSD-3-Clause | Go support libraries used by the application and its services. |

Xray's Shadowsocks-2022 package is imported by `xray-runtime` and in turn uses
`sing` and `sing-shadowsocks`. These modules are included in the statically
linked runtime, not just present as unused module metadata. Their upstream
licenses state GPL-3.0-or-later. The project has selected GPL-3.0-or-later for
project-authored code and binaries. Xray-core's MPL-2.0 terms and all other
third-party license terms continue to apply to their respective components.
The matching source tag and the pinned module versions and checksums provide
the inputs needed to retrieve the runtime's corresponding source. This notice
is an inventory, not a legal opinion.

The Go manifests below list the direct and indirect modules selected for each
binary. The `go.sum` files hold module checksums and can also retain entries for
versions no longer selected by the current build:

- [`go.mod`](go.mod), [`go.sum`](go.sum) — control-plane, controller,
  lease-service, and installer binaries.
- [`awg-service/go.mod`](awg-service/go.mod), [`awg-service/go.sum`](awg-service/go.sum) — AmneziaWG service.
- [`awg-contract/go.mod`](awg-contract/go.mod), [`awg-contract/go.sum`](awg-contract/go.sum) — shared gRPC/Protocol Buffer contract.
- [`xray-runtime/go.mod`](xray-runtime/go.mod), [`xray-runtime/go.sum`](xray-runtime/go.sum) — embedded Xray runtime and its transitive modules.

## Web application

The shipped web UI uses [Vue](https://github.com/vuejs/core) `3.5.43` and
[Zod](https://github.com/colinhacks/zod) `4.6.5`, both MIT-licensed. The web
build, type-check, lint, and test toolchain also uses Vite, Vitest, TypeScript,
`vue-tsc`, ESLint and plugins, `@vue/test-utils`, and jsdom. Direct development
dependencies are declared in [`web/package.json`](web/package.json). The
[`web/package-lock.json`](web/package-lock.json) records all 293 resolved npm
package records, including transitive and platform-specific packages, their
versions, and license metadata. Development tools are used at build/test time;
the final control-plane image contains the built web assets.

## Other bundled and build-time tools

| Component | Version | License | Use |
| --- | --- | --- | --- |
| [mkcert](https://github.com/FiloSottile/mkcert) | `v1.4.4` | BSD-3-Clause | Binary included in the control-plane and Hysteria TLS-init images to generate certificates. |
| [Buf CLI](https://github.com/bufbuild/buf) | `1.57.2` | Apache-2.0 | Build-time Protocol Buffer generator, invoked by `scripts/generate-protobuf.sh`. |
| [protoc-gen-go](https://github.com/protocolbuffers/protobuf-go) | `v1.36.6` | BSD-3-Clause | Remote generator configured in `buf.gen*.yaml`; generated Go code is checked in. |
| [protoc-gen-go-grpc](https://github.com/grpc/grpc-go) | `v1.5.1` | Apache-2.0 | Remote gRPC generator configured in `buf.gen*.yaml`; generated Go code is checked in. |
| [Liquid Glass Vue](https://github.com/wxperia/liquid-glass-vue) | `1.0.9` | MIT | Inspiration for the button refraction filter in `web/src/presentation/LiquidGlassFilter.vue`; it is not a project dependency and its implementation is not vendored. License text: [`third_party/licenses/WXPERIA-LIQUID-GLASS-VUE-MIT-LICENSE`](third_party/licenses/WXPERIA-LIQUID-GLASS-VUE-MIT-LICENSE). |

## Container images and operating-system packages

Runtime and initialization images use Alpine Linux `3.22`. The AWG and
Hysteria TLS-init images install Alpine packages `ca-certificates`, `iproute2`,
`iptables`, and `openssl` as applicable. Build stages use `golang:1.27.1-alpine`
and `node:24-alpine`. These images and packages have their own upstream licenses;
the repository does not pin image digests or Alpine package revisions, so the
exact package set in a built image depends on the image and package repository
state at build time.
