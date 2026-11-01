# Security Policy

## Reporting a vulnerability in mcp-audprobe

Please **do not** open a public issue for security problems.

Use GitHub's private vulnerability reporting:
**[Report a vulnerability](https://github.com/bymustfa/mcp-audprobe/security/advisories/new)**
(repository → *Security* tab → *Report a vulnerability*). You will get an acknowledgement as soon as the
maintainer can, and we will coordinate a fix and disclosure with you.

Examples of in-scope issues: the safety guard (`--allow-remote` / loopback check) can be bypassed, the tool
leaks signing keys or raw tokens, the fake authorization server exposes more than JWKS/metadata, command
injection in `action.yml`, or unsafe handling of untrusted server responses.

## Supported versions

Only the latest release/`main` is supported while the project is pre-1.0.

## Responsible use

mcp-audprobe is a testing tool. Use it only against servers you own or are authorized to test. Findings it
reports about *your* servers (e.g. missing audience validation) should be fixed in those servers. For issues in
third-party software, follow that project's own disclosure process, e.g. the advisories linked in the
[README](README.md).
