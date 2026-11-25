# Security vulnerability disclosure

This file is the **vulnerability disclosure process for this plugin repository (`kore-plugin-waf`)**, not a security design document.

## Scope

Covered: the implementation of the WAF plugin (id `waf`), the capability declarations in `info.json`, the `web/` frontend, and the `make dist` artifacts.

Not covered: kernel and protocol issues — please report them per [kore SECURITY.md](https://github.com/kore-pl/kore/blob/main/SECURITY.md); known vulnerabilities in upstream third-party dependencies should also be reported to the upstream.

## Supported versions

| Version | Status | Notes |
| --- | --- | --- |
| `0.5.1` (current latest) | ✅ Accepts and fixes | Security fixes are provided only for the latest patch version |
| Earlier `0.x` versions | ❌ Not supported | Please upgrade to the latest version first |

During the 0.x phase we use a minimal support surface: only the latest patch version of a given minor line receives fixes; older patch versions are not backported individually.

## Attack surface in this repository

- **RPC methods**: all `waf.*` methods (see `README.md` for the method table); missing parameter validation can lead to privilege escalation or injection.
- **capabilities**: `info.json.capabilities` is the entire authorization surface of this plugin; every additional declaration is an additional attack path.
- **Separate process and UDS**: the plugin runs as a separate process; the socket is created by the main shell, `chown kore-<id>`, with permissions `0600`; bypassing socket permissions or connecting to another party's socket is a vulnerability.
- **Host write surface**: write capabilities actually granted through `capabilities` (files / processes / network / database, etc.); writes beyond the declared scope are vulnerabilities.
- **Frontend**: `web/` runs inside an iframe with an independent origin and communicates with the main shell via postMessage; XSS, message forgery, or cross-plugin data reads are all security boundary issues.

## Reporting

1. **Preferred: GitHub Security Advisory**: this repository's Security page → "Report a vulnerability" (private channel, does not create a public issue).
2. **Backup email**: `pengtang1024@users.noreply.github.com`, with subject `[kore security] waf`.
3. **Do not open public issues, and do not post PoCs in discussions or PRs.**
4. Please include in your report: affected version, reproduction steps or PoC, impact assessment, whether it is already public, and your attribution preference.

## Timeline and disclosure

- **Within 72 hours** we acknowledge receipt and give a first assessment; for complex cases we share an investigation plan.
- After a fix, disclosure is coordinated with a default **90-day** window; if the issue is actively exploited and earlier disclosure is needed, please contact us first.
- After the fix is released, record the security fix in `CHANGELOG.md` (without exploit details) and publish a security advisory as needed.

## Acknowledgements

With your consent we thank you in the release notes; if you prefer not to be named, you will be credited anonymously.
