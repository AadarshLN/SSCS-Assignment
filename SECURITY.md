# Security Policy

## Supported versions

Only the latest version on the `main` branch receives security updates.

| Version | Supported |
|---|---|
| `main` (latest) | Yes |
| Older commits and branches | No |

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues, pull requests or discussions.**

Report them privately using **GitHub private vulnerability reporting :** go to the repository's **Security** tab and click **Report a vulnerability**.

Please include:

- A description of the vulnerability and its potential impact
- Steps to reproduce it, or a proof of concept
- The affected file(s), function(s) and commit hash
- Any suggested fix, if you have one

## What to expect

| Step | Timeline |
|---|---|
| Acknowledgement of your report | Within 3 business days |
| Initial assessment and severity rating | Within 7 days |
| Fix released for confirmed critical or high severity issues | Within 30 days |

You will be informed of the progress and will be informed when the issue is resolved. If the report is declined the explanation for the same will be provided. 

## How security updates are handled

1. The report is reproduced and assessed privately.
2. A fix is developed on a private branch or a GitHub security advisory fork.
3. The fix is reviewed, tested, and merged to `main` through a pull request.
4. A GitHub Security Advisory is published describing the issue, affected versions and the fix. Reporters are credited unless they prefer to remain anonymous.

## Scope

In scope:

- Incorrect verification results (e.g. an invalid signature or a tampered proof reported as valid)
- Bugs in Merkle proof verification or certificate handling
- Leaked secrets or credentials in the repository
- Vulnerable dependencies

Out of scope:

- Vulnerabilities in the Rekor service itself. Report those to the [Sigstore project](https://github.com/sigstore/rekor/security/policy).
