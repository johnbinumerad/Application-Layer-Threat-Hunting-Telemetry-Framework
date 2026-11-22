# Attack Mapping

Each scenario is mapped to MITRE ATT&CK technique IDs and an OWASP API Security Top 10 (2023) category. The ATT&CK IDs match the `attack.*` tags in `detections/sigma/*.yml`.

| Scenario (`lab.ground_truth.scenario`) | Simulator | Weakness endpoint | OWASP API Top 10 | ATT&CK techniques |
|---|---|---|---|---|
| `bola` | `simulators/hunt_01_bola_enum.py` | `GET /api/v1/invoices/{id}` | API1:2023 Broken Object Level Authorization | T1087 Account Discovery; T1213 Data from Information Repositories |
| `jwt` (`alg_none`, `expired`, `hijack`) | `simulators/hunt_02_jwt_abuse.py` | `GET /api/v1/admin/audit`, `GET /api/v1/invoices/{id}` | API2:2023 Broken Authentication | T1550.001 Use Alternate Authentication Material: Application Access Token; T1078 Valid Accounts |
| `ssrf` | `simulators/hunt_03_ssrf_egress.py` | `POST /api/v1/webhooks/preview` | API7:2023 Server Side Request Forgery | T1190 Exploit Public-Facing Application; T1552.005 Unsecured Credentials: Cloud Instance Metadata API |

## Detections per scenario

| Scenario | Sigma file |
|---|---|
| `bola` | `detections/sigma/bola_enumeration.yml` |
| `jwt` | `detections/sigma/jwt_abuse.yml` |
| `ssrf` | `detections/sigma/ssrf_egress.yml` |

The `baseline` scenario (`simulators/traffic_baseline.py`) is benign traffic and has no ATT&CK mapping.

Note: `lab.ground_truth.technique` holds the simulator's technique name (for example `idor_enumeration`, `alg_none`, `expired`, `hijack`, `metadata_service`, `internal_service`, `alt_encoding`, `dns_alias`), not an ATT&CK ID. The ATT&CK mapping lives in this document and in the Sigma tags.
