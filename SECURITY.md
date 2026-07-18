# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 2.0.x | Yes |
| Earlier versions | No |

Security fixes are targeted at the current 2.0.x line. Users should reproduce reports against the latest available 2.0.x revision when practical.

## Reporting a vulnerability

Please do not disclose a suspected vulnerability publicly before maintainers have had a reasonable opportunity to investigate and remediate it.

Use this repository's [private vulnerability reporting or Security Advisory flow](https://github.com/mevorahde/pw_locker/security/advisories/new). Do not include live credentials, real vault contents, master passwords, encryption keys, or other sensitive personal data in a report.

A useful report includes:

- Clear reproduction steps or a minimal proof of concept
- The affected Password Locker version and relevant platform details
- The expected and observed behavior
- The potential security impact
- A suggested mitigation, if one is known

The project aims to acknowledge security reports within seven calendar days as a best-effort target. This is not a guaranteed response or remediation deadline. Investigation time will vary with severity, reproducibility, and maintainer availability.

## Security boundaries and known limitations

Password Locker is a local encrypted vault, not an enterprise secret-management service. Its authenticated encryption protects stored credential passwords from offline disclosure and undetected record modification when the master password and host remain trustworthy. Important boundaries include:

- Forgotten master passwords cannot be recovered.
- Master-password rotation is not currently implemented.
- Account names and record counts remain visible in SQLite metadata.
- Clipboard confidentiality depends on the operating system and other applications.
- Filesystem access controls depend on the host operating system.
- Python cannot guarantee complete in-memory secret zeroization.
- Database rollback or replacement protection requires external backup or filesystem controls.
- The legacy `users.db` format is unsupported and is not automatically migrated.
- The project has not received an independent professional security audit.

These limitations should be considered before deciding whether the application fits a particular threat model. Do not submit real secrets as test data when reporting a vulnerability.

## Bugs and feature requests

Normal bugs, usability reports, documentation corrections, and feature requests belong in the repository's public [GitHub Issues](https://github.com/mevorahde/pw_locker/issues). Use private vulnerability reporting only for issues with a plausible security impact.
