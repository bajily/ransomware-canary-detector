# Ransomware Canary Detector

Ransomware behavior triage using canary file events, rolling host activity windows, mass file changes and unusual extension transitions.

Correlate exported filesystem events and canary touches into host-level triage findings.

**Python 3.11+ · Standard library · JSON, SARIF 2.1.0 and Markdown reports · MIT license**

## Quick start

```bash
git clone https://github.com/bajily/ransomware-canary-detector.git
cd ransomware-canary-detector
python security_tool.py --demo --now 2026-10-13T12:00:00Z
python -m unittest discover -v
```

The synthetic example intentionally contains risky conditions. Exit status `1` means a finding met the configured threshold; it is not a crash.

```bash
python security_tool.py example.json --format sarif --output findings.sarif
python security_tool.py example.json --format markdown --output review.md --fail-on critical
python security_tool.py example.json --policy policy.json --suppressions exceptions.json
```

## How the review works

Correlate exported filesystem events and canary touches into host-level triage findings.

Implemented rule families: `RANSOM-CANARY-TOUCH`, `RANSOM-MASS-CHANGES`.

Each finding includes a rule ID, severity, resource, evidence, a recommended review action and a stable fingerprint. Reports sort findings by severity and resource. No automatic enforcement is performed.

## Input contract

The example below is the minimal supported export structure. Required fields are validated; malformed or ambiguous inputs cause exit status 2.



```json
{
  "events": [
    {
      "timestamp": "2026-10-13T11:00:00Z",
      "host": "synthetic-workstation",
      "actor": "synthetic-process",
      "operation": "rename",
      "path": "records/file0.txt",
      "new_path": "records/file0.locked"
    },
    {
      "timestamp": "2026-10-13T11:00:01Z",
      "host": "synthetic-workstation",
      "actor": "synthetic-process",
      "operation": "rename",
      "path": "records/file1.txt",
      "new_path": "records/file1.locked"
    },
    {
      "timestamp": "2026-10-13T11:00:02Z",
      "host": "synthetic-workstation",
      "actor": "synthetic-process",
      "operation": "rename",
      "path": "records/file2.txt",
      "new_path": "records/file2.locked"
    },
    {
      "timestamp": "2026-10-13T11:00:03Z",
      "host": "synthetic-workstation",
      "actor": "synthetic-process",
      "operation": "rename",
      "path": "records/file3.txt",
      "new_path": "records/file3.locked"
    },
    {
      "timestamp": "2026-10-13T11:00:04Z",
      "host": "synthetic-workstation",
      "actor": "synthetic-process",
      "operation": "rename",
      "path": "records/file4.txt",
      "new_path": "records/file4.locked"
    },
    {
      "timestamp": "2026-10-13T11:00:05Z",
      "host": "synthetic-workstation",
      "actor": "synthetic-process",
      "operation": "rename",
      "path": "records/file5.txt",
      "new_path": "records/file5.locked"
    },
    {
      "timestamp": "2026-10-13T11:00:06Z",
      "host": "synthetic-workstation",
      "actor": "synthetic-process",
      "operation": "rename",
      "path": "records/file6.txt",
      "new_path": "records/file6.locked"
    },
    {
      "timestamp": "2026-10-13T11:00:07Z",
      "host": "synthetic-workstation",
      "actor": "synthetic-process",
      "operation": "rename",
      "path": "records/file7.txt",
      "new_path": "records/file7.locked"
    },
    {
      "timestamp": "2026-10-13T11:00:08Z",
      "host": "synthetic-workstation",
      "actor": "synthetic-process",
      "operation": "rename",
      "path": "records/file8.txt",
      "new_path": "records/file8.locked"
    },
    {
      "timestamp": "2026-10-13T11:00:09Z",
      "host": "synthetic-workstation",
      "actor": "synthetic-process",
      "operation": "rename",
      "path": "records/file9.txt",
      "new_path": "records/file9.locked"
    },
    {
      "timestamp": "2026-10-13T11:00:15Z",
      "host": "synthetic-workstation",
      "actor": "synthetic-process",
      "operation": "write",
      "path": "records/canary.txt"
    }
  ]
}
```

Identifiers in examples are synthetic. Adapt exports to this exact shape instead of assuming provider APIs use identical field names.

## Policy and integration

Policy defaults and the input fields are documented below and in the audit function. Review thresholds before operational use.

```json
{
  "window_seconds": 60,
  "unique_file_threshold": 8,
  "destructive_ratio": 0.6,
  "canary_patterns": [
    "**/canary.txt",
    "canary.txt"
  ],
  "suspicious_suffixes": [
    ".locked",
    ".encrypted",
    ".crypt"
  ],
  "excluded_actors": []
}
```

The empty object selects defaults. Every input file is limited to 10 MiB. Duplicate JSON keys and non-finite numbers are rejected. Timestamps require explicit timezones. `--now` makes time-dependent reviews reproducible.

Exit statuses: `0` means no active finding meets `--fail-on`; `1` means the threshold is met; `2` means invalid input or an operational error. Output files are created exclusively and existing evidence is not overwritten. A clean report does not establish that a system is secure.

## Reviewed exceptions

Use a finding's exact fingerprint, an explanation and an expiration date:

```json
[
  {"fingerprint": "COPY-A-FINDING-FINGERPRINT", "reason": "Approved temporary exception; ticket SEC-123", "expires": "2027-01-01T00:00:00Z"}
]
```

Expired exceptions stop suppressing findings. Suppressed findings remain in JSON evidence. Keep exception review separate from code changes.

## Validation and deployment limits

Unit tests exercise the detector, clean inputs, boundary conditions, report generation, input failures and exception expiry. GitHub Actions runs the suite on Python 3.11 and 3.14.

It does not deploy a sensor, execute ransomware, kill processes or isolate devices. Backups, installers and bulk maintenance may resemble the rules; validate local exclusions and thresholds.

Version 0.1.0 is an initial implementation for controlled evaluation. Establish a company-specific baseline, test representative sanitized exports, review false positives and perform an independent security review before relying on it operationally. These projects have no measured production performance or effectiveness claims.

## Security and contributions

Keep secrets, private inventories, real email, signing keys and sensitive logs out of public issues and repositories. Publish only synthetic or sanitized fixtures. Findings and generated reports can contain private asset identifiers; protect them as internal security records.

For a suspected vulnerability, use GitHub private reporting if available. Otherwise describe the issue without secrets or sensitive exploit details. Include a reproducible synthetic test with focused changes, and run the test suite before proposing a contribution.

## بالعربية

أداة دفاعية لتحليل الأدلة الأمنية وإنتاج نتائج قابلة للمراجعة مع قواعد واضحة واختبارات. تعمل على مدخلات موثقة وتدعم ضبط السياسات والاستثناءات المؤقتة. يلزم تقييمها على بيئة الشركة قبل الاعتماد التشغيلي؛ لا تقدّم ضمانًا شاملًا لحماية الأنظمة.
