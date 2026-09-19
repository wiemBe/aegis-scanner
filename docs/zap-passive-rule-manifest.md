# ZAP supply chain and passive-rule manifest (Phase 1.3)

`src/aegis_zap/manifest.json` (schema `aegis.zap.manifest/1`, manifest version `1.3.0`) is the only
source of truth for what the zap-runner may contain and enable. Controller and runner each compute
its SHA-256 independently; an execution proceeds only when both agree. Changing any pin, rule or
threshold requires a reviewed manifest version bump and a fresh acceptance matrix.

## Frozen engine

| Item | Pin |
| --- | --- |
| ZAP release | `2.17.0` (published 2026-08-07, Apache-2.0) |
| Image | `docker.io/zaproxy/zap-stable` (observed tag `2.17.0`; never referenced by tag) |
| OCI index digest | `sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef` |
| linux/arm64 manifest | `sha256:05cbf4cab5d2fdaef55b0cd0b586f22d0ce4f75e0995f3cea2db23afbbdfd2f8` |
| linux/amd64 manifest | `sha256:71db37cd5b75663b35758d10aaec05bf6fbac23f5020e3046c70e628a5f84efa` |
| `zap-2.17.0.jar` | `015dda4709b5ef79736086bb41e8e2a4e95b04cf6625f14d6bcc02b197c99c0c` (identical on both architectures) |
| Java runtime | OpenJDK `17.0.20` (`17.0.20+8-1-deb12u1-Debian`) |
| JVM (arm64) | `java` `96c4c2f2…`, `libjvm.so` `35dc1132…`, `release` `8332845d…` |
| JVM (amd64) | `java` `8e2c39b4…`, `libjvm.so` `68fb1aff…`, `release` `2107e350…` |
| Automation Framework | `automation` add-on `0.60.0` |
| SBOM | none published upstream; the image package inventory (`dpkg-query`) is recorded in the evidence instead |

The upstream image ships two versions of many add-ons (bundled plus updated). The derived runner
image keeps **exactly eight** add-on files — the ones ZAP itself loads — and deletes everything else:

| Add-on | Version | Status | File SHA-256 | Why |
| --- | --- | --- | --- | --- |
| automation | 0.60.0 | beta | `e02c90ab…` | runs the fixed plan only |
| callhome | 0.23.0 | release | `eadebd4a…` | mandatory core add-on; neutralised (silent, telemetry off, no route) |
| commonlib | 1.43.0 | release | `f1c46d6c…` | shared library |
| network | 0.29.0 | beta | `082367cc…` | HTTP client, proxied through the guard |
| openapi | 57.0.0 | beta | `fe87dd63…` | local `apiFile` import |
| pscan | 0.6.0 | alpha | `269ff66f…` | passive scanner + wait job |
| pscanrules | 75.0.0 | release | `97814c5f…` | release passive rules (all but the admitted one disabled) |
| reports | 0.46.0 | release | `2e8d42a4…` | local `traditional-json` report |

Full digests are in the manifest. Forbidden add-on ids (their presence makes the runner NOT READY)
include `ascanrules*`, `spider`, `spiderAjax`, `client`, `scripts`, `graaljs`, `zest`, `fuzz`,
`oast`, `replacer`, `requester`, `sequence`, `graphql`, `soap`, `postman`, `selenium`, `hud`,
`bruteforce`, `mcp` and `llm`.

## Drift detection

- **Build time:** the runner Dockerfile verifies the jar, per-architecture JVM files and every kept
  add-on against the manifest and fails the build on any mismatch.
- **Boot:** the runner re-hashes the jar, JVM files and plugin directory (exact file set), runs
  `java -version`, then asks the pinned ZAP itself (`-cmd -silent -notel -addonlist`) which add-ons
  it loads and checks ZAP's own `zap.log` (`Installed add-ons: [...]`, silent-mode line, no active
  rules). Any difference leaves the runner NOT READY.
- **Every execution:** jar, JVM and plugin files are re-hashed before start; ZAP's per-execution
  `zap.log` must again list exactly the manifest add-ons and confirm silent mode; the controller
  checks the attested inventory digest, versions, forbidden-add-on and unexpected-file counts.

## Passive rule manifest

Only one rule is admitted in Phase 1.3. The plan sets `disableAllRules: true` and then enables
exactly the manifest rules; ZAP's own output must confirm exactly that rule set.

| Field | Value |
| --- | --- |
| Rule / plugin id | `10021` — X-Content-Type-Options Header Missing |
| Add-on | `pscanrules` `75.0.0` (release quality) |
| Implementation | `org.zaproxy.zap.extension.pscanrules.XContentTypeOptionsScanRule` |
| Threshold | `MEDIUM` (unmodified default behaviour; nothing tuned to force a match) |
| ZAP claim | risk `low`, confidence `medium` — recorded as **untrusted** metadata only |
| Risk/confidence policy | `UNTRUSTED_TOOL_METADATA_NEVER_SETS_AEGIS_SEVERITY_OR_CONFIDENCE` |
| Expected evidence fields | `uri`, `method`, `param` (`x-content-type-options`) |
| Aegis capability | `zap_passive_header_openapi_v1` |
| Verification policy | `DETERMINISTIC_AEGIS_VERIFIER` (`aegis-zap-header-verifier/1.3.0`) |
| Aegis severity on VERIFIED | `LOW` (catalog-owned) |
| Justification | release-quality, response-only, sends no requests; deterministic condition creatable and patchable on one synthetic route; independently re-checkable with a fresh GET |
| Review | 2026-09-19, AI-assisted technical admission review, `operator_countersigned: false` |

The parser rejects any alert whose plugin id is not in this manifest, or whose name differs from the
manifest name, and the controller rejects any alert whose rule id is not in the job.
