# Comparison with other tools

English | [日本語](comparison.ja.md)

FileAccessMonitor aims at one job: letting a small team see who read, changed, or deleted files on their file servers, without building a log platform. If you need more than that, another tool is likely a better fit.

| | FileAccessMonitor | Commercial auditing products<br>(e.g. Netwrix Auditor, ManageEngine ADAudit Plus) | Wazuh |
|---|---|---|---|
| Cost | Free (MIT) | Paid licenses | Free (open source); paid cloud and support available |
| Setup | One installer on the file server; an agent on each further file server | Installer; often needs a separate server and database | Wazuh server, indexer, and dashboard, plus an agent on each host |
| Scope | File access on Windows file servers and Linux Samba file servers | File servers, NAS, Active Directory, Microsoft 365, and more | Security monitoring (SIEM/XDR) across many hosts |
| Who **read** a file | Yes (Security log events 4663/4659; Samba's audit module on Linux) | Yes | File integrity monitoring covers changes only; reads need Security-log collection and your own rules |
| Multiple servers in one view | Yes (agents send to one monitoring server) | Yes | Yes |
| Alerts | Mass delete / change / read, bursts of refused access, ransomware-like behaviour (high priority, no automatic response), and gaps in recording, to Teams, Slack, a webhook, or email | Many built-in rules | Flexible rules and automated responses |
| Failed (refused) access | Yes (recorded as **Denied**) | Yes | Needs Security-log collection and your own rules |
| Permission changes | Yes (Windows with details; Linux without before/after) | Yes | Needs Security-log collection and your own rules |
| Reports | Search and CSV export | Built-in compliance and scheduled reports | Dashboards and compliance mappings |
| Japanese UI | Yes | Varies by product | No |
| Support | Community (GitHub Issues), no SLA | Vendor support | Community, or paid vendor support |

**When to choose which**

- **FileAccessMonitor**: you have one or several Windows or Samba file servers, want answers to "who deleted this file?" or "who opened this folder?", and do not want to run a log platform.
- **A commercial product**: you need to audit NAS appliances, AD, or Microsoft 365 together with the file servers, need compliance reports, or need vendor support.
- **Wazuh**: you are building organization-wide security monitoring and file access is one of many sources.

Product capabilities above are summarized from public information and may change. Check each vendor's documentation for details.
