# Security Policy

PortPeek is a network reconnaissance tool. We take its own security, and
the responsible-use expectations around it, seriously.

## Reporting a Vulnerability

Please report security vulnerabilities using [GitHub Security
Advisories](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
for this repository: go to the **Security** tab → **Advisories** → **Report
a vulnerability**. This opens a private report visible only to the
maintainers until a fix is ready, so details aren't disclosed before users
can update.

Please do not report security issues through public GitHub issues,
discussions, or pull requests.

When reporting, please include:

- A description of the vulnerability and its potential impact.
- Steps to reproduce it (a minimal example is very helpful).
- The PortPeek version and platform you tested on.

We aim to acknowledge new reports within a few days. Since this is a
community-maintained project without a dedicated security team or SLA,
response and fix timelines will vary, but security reports are prioritized
over ordinary feature work.

## Supported Versions

PortPeek is pre-1.0 software. Security fixes are made against the latest
released minor version; we don't maintain parallel security patches for
older releases at this stage. Once the project reaches 1.0, this policy
will be revisited and documented here.

## Scope and Intended Use

PortPeek is built around a conservative, authorized-use-only safety
posture:

- It performs lightweight, non-destructive TCP connect scanning and
  passive/active banner-style fingerprinting only.
- It never attempts exploitation, credential attacks, brute forcing,
  vulnerability exploitation, or stealth/evasion techniques.
- An open port is reported as an open port — PortPeek never claims a
  vulnerability merely from port state or a service banner.

**Only scan systems you own or have explicit, documented authorization to
assess.** Scanning systems without authorization may be illegal in your
jurisdiction and is outside the intended and supported use of this tool.
Misuse of PortPeek against systems you do not have permission to test is
not a security vulnerability in PortPeek itself and is not in scope for
this policy — but if you discover that PortPeek's own behavior could make
unauthorized misuse easier (e.g., a way to bypass its safety posture), that
*is* in scope and we want to hear about it.

## What Counts as a Vulnerability Here

Examples of in-scope reports:

- A way to make PortPeek perform actions beyond its documented
  non-destructive scanning/fingerprinting behavior (e.g., something that
  behaves like an exploit, a credential attack, or a destructive probe).
- SQL injection, path traversal, or other local data-handling flaws in how
  PortPeek reads/writes its SQLite database or config.
- A crash or resource exhaustion triggerable by a malicious remote host
  PortPeek merely scans (PortPeek should degrade gracefully against
  hostile or malformed responses, never panic or hang indefinitely).
- Supply-chain concerns in PortPeek's own build (e.g., its `go.sum`).

Examples of out-of-scope reports:

- "PortPeek can be used to scan a network" — that's its documented
  purpose, subject to the authorized-use expectation above.
- Feature requests for more aggressive scanning, exploitation, or evasion
  capabilities. These are explicitly against this project's design
  philosophy and will not be added, security report or not.
