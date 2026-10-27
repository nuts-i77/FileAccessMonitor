# Security Policy

## Supported versions

Only the latest release (or the `main` branch) receives security fixes.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Use GitHub's private reporting instead: open the repository's **Security** tab and choose **Report a vulnerability**. Reports in English or Japanese are welcome.

Please include:

- The affected version or commit
- Steps to reproduce, or a proof of concept
- The impact you expect (for example, authentication bypass or access to audit records)

You can expect an initial response within 7 days. Once a fix is available, we will publish a GitHub Security Advisory and credit you unless you prefer to stay anonymous.

## Scope

In scope:

- The web API and web GUI (authentication, authorization, input handling)
- Handling of the secrets in `C:\ProgramData\FileAccessMonitor\` (`jwt.key`, `initial-admin-password.txt`)
- The PowerShell scripts in this repository

Out of scope:

- Running the service over plain HTTP on an untrusted network. HTTPS is opt-in; see the README.
- Attacks that require local Administrator or SYSTEM access to the server. Those accounts can read the Security event log directly.
- Vulnerabilities in Windows itself or in the bundled third-party libraries. Please report those upstream.

---

## 脆弱性の報告（日本語）

公開 Issue ではなく、リポジトリの **Security** タブ → **Report a vulnerability**（非公開報告）からご連絡ください。日本語でも構いません。
