# Security Policy

## Supported Versions

HO-Azure-Lab is currently maintained on the latest main development line.

| Version | Supported |
| --- | --- |
| 0.x | Yes |

## Reporting A Vulnerability

Please do not open public GitHub issues for suspected security vulnerabilities.

Preferred path:

- use GitHub private vulnerability reporting or a private security advisory if it is available

If private reporting is not available, contact the maintainer directly through GitHub rather than
posting a public issue with exploit details.

When reporting, please include:

- affected version or commit
- reproduction steps
- impact and scope
- any suggested remediation or mitigation

## Scope Notes

HO-Azure-Lab intentionally provisions an insecure-by-design proof environment so `HO-Azure` can be
validated against realistic cloud posture and attack-surface signals.

Reports that the lab contains intentionally risky Azure posture, broad permissions, or proof-only
objects are generally not treated as product vulnerabilities by themselves.

Useful security reports usually involve one of these:

- accidental credential or secret exposure in the repo or release artifacts
- accidental publication of live environment identifiers that should have remained private
- supply-chain, workflow, or release-process weaknesses
- output, docs, or validation logic that materially overstate proof or safety boundaries
- unsafe file handling, command execution, or similar implementation flaws in HO-Azure-Lab itself
