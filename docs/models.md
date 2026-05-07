# Phantom Framework — Data Models

This document catalogs every SQLAlchemy model in `backend/app/models/`. All models inherit from `BaseModel`, which provides `id`, `created_at`, and `updated_at`.

---

## BaseModel

**File:** `base.py` · **Abstract:** yes

Common fields shared by every concrete model.

| Field        | Type     | Notes                          |
|--------------|----------|--------------------------------|
| `id`         | Integer  | Primary key, indexed           |
| `created_at` | DateTime | Server-set on insert           |
| `updated_at` | DateTime | Server-set on update           |

---

## Vault

**File:** `vault.py` · **Table:** `vaults`

A bug bounty program container. Holds scope rules and groups all targets, workflows, and notes for one program.

| Field           | Type           | Notes                                                  |
|-----------------|----------------|--------------------------------------------------------|
| `name`          | String(255)    | Indexed, not null                                      |
| `platform`      | Enum           | `PlatformType` — defaults to `CUSTOM`                  |
| `target_domain` | String(255)    | Not null                                               |
| `program_url`   | String(255)    | Optional — URL to bounty program page                  |
| `scope_rules`   | JSON           | `{"in": [...], "out": [...]}` — fnmatch wildcards      |

**Relationships:** `targets` (1→N), `workflows` (1→N), `notes` (1→N)

**Methods:** `is_in_scope(domain)`, `is_out_scope(domain)` — fnmatch-based scope checks; out-patterns override in-patterns.

### `PlatformType` enum
`HACKERONE`, `BUGCROWD`, `INTIGRITI`, `YESWEHACK`, `CUSTOM`

---

## Target

**File:** `target.py` · **Table:** `targets`

A specific asset inside a Vault. Self-referential — supports hierarchical relationships (Domain → Subdomain → Endpoint).

| Field             | Type        | Notes                                       |
|-------------------|-------------|---------------------------------------------|
| `identifier`      | String(512) | Indexed, not null                           |
| `target_type`     | Enum        | `TargetType` — defaults to `WEB`            |
| `vault_id`        | FK → vaults | `SET NULL` on delete                        |
| `parent_id`       | FK → targets| Self-referential, `SET NULL` on delete      |
| `status`          | Enum        | `TargetStatus` — defaults to `ACTIVE`       |
| `is_wildcard`     | Boolean     | Default `False`                             |
| `ip_address`      | String(45)  | IPv4/IPv6                                   |
| `tech_stack`      | JSON        |                                             |
| `risk_score`      | Integer     | Default `0`                                 |
| `description`     | Text        |                                             |
| `last_scanned_at` | DateTime    |                                             |

**Relationships:** `vault`, `children`/`parent`, `assets` (1→N), `scans` (1→N), `findings` (1→N), `notes` (1→N)

**Methods:** `mark_scanned()` — updates `last_scanned_at`.

### `TargetType` enum
`WEB`, `API`, `MOBILE`, `NETWORK`, `CLOUD`, `OTHER`

### `TargetStatus` enum
`ACTIVE`, `ARCHIVED`, `BLACKLISTED`, `VULNERABLE`

---

## Asset

**File:** `asset.py` · **Table:** `assets`

Universal intelligence storage — every piece of discovered information becomes an Asset. Self-referential and deduplicated via SHA256 hash.

| Field              | Type        | Notes                                                |
|--------------------|-------------|------------------------------------------------------|
| `target_id`        | FK → targets| `CASCADE` on delete, indexed                         |
| `asset_type`       | Enum        | `AssetType`, indexed                                 |
| `status`           | Enum        | `AssetStatus` — defaults to `NEW`                    |
| `value`            | Text        | Not null                                             |
| `asset_metadata`   | JSON        | Default `{}`                                         |
| `asset_source`     | String(100) | E.g., scanner module name                            |
| `asset_confidence` | Integer     | Default `100`                                        |
| `asset_hash`       | String(64)  | Unique, indexed — SHA256 for dedup                   |
| `is_active`        | Boolean     | Default `True`                                       |
| `is_sensitive`     | Boolean     | Default `False`                                      |
| `first_seen_at`    | DateTime    | Not null                                             |
| `last_seen_at`     | DateTime    | Not null                                             |
| `last_verified_at` | DateTime    |                                                      |
| `parent_asset_id`  | FK → assets | Self-referential, `SET NULL` on delete               |

**Indexes:** `(target_id, asset_type)`, `(status, is_active)`

**Relationships:** `target`, `parent`/`children`

**Methods:** `mark_seen()`, `mark_verified()`, `mark_changed()`, `create_hash(target_id, asset_type, value)` (classmethod). Uses a `before_insert` event to auto-generate `asset_hash`.

### `AssetType` enum
`SUBDOMAIN`, `IP_ADDRESS`, `PORT`, `SERVICE`, `URL`, `ENDPOINT`, `PARAMETER`, `HEADER`, `COOKIE`, `JAVASCRIPT`, `TECHNOLOGY`, `SSL_CERT`, `DNS_RECORD`, `EMAIL`, `CREDENTIAL`, `API_KEY`, `FORM`, `WEBSOCKET`, `GRAPHQL_SCHEMA`, `S3_BUCKET`, `CLOUD_RESOURCE`

### `AssetStatus` enum
`NEW`, `VERIFIED`, `CHANGED`, `REMOVED`, `MONITORED`

---

## Scan

**File:** `scan.py` · **Table:** `scans`

A scan operation execution — links a Target to the Module that ran against it.

| Field               | Type        | Notes                                            |
|---------------------|-------------|--------------------------------------------------|
| `target_id`         | FK → targets| `CASCADE` on delete, indexed                     |
| `module_id`         | FK → modules| `SET NULL` on delete                             |
| `scan_type`         | Enum        | `ScanType`, not null                             |
| `status`            | Enum        | `ScanStatus` — defaults to `QUEUED`              |
| `config`            | JSON        | Per-scan config, default `{}`                    |
| `result_summary`    | JSON        | Default `{}`                                     |
| `error_message`     | Text        |                                                  |
| `assets_discovered` | Integer     | Default `0`                                      |
| `findings_count`    | Integer     | Default `0`                                      |
| `started_at`        | DateTime    | Not null                                         |
| `completed_at`      | DateTime    |                                                  |
| `duration_seconds`  | Integer     |                                                  |
| `triggered_by`      | String(50)  | Default `'manual'`                               |

**Indexes:** `(target_id, status)`, `(module_id, scan_type)`

**Relationships:** `target`, `module`, `findings` (1→N)

**Methods:** `start()`, `complete()` (sets duration), `fail(error)` (records error + duration).

### `ScanType` enum
`SUBDOMAIN_ENUM`, `JAVASCRIPT_ANALYSIS`, `SERVICE_DETECTION`, `DNS_RESOLUTION`, `PORT_SCAN`, `WEB_CRAWL`, `TECHNOLOGY_DETECTION`, `SSL_ANALYSIS`, `VULNERABILITY_SCAN`, `CUSTOM_SIGNATURE`, `FULL_RECON`

### `ScanStatus` enum
`QUEUED`, `RUNNING`, `PAUSED`, `COMPLETED`, `CANCELLED`, `FAILED`

---

## Finding

**File:** `finding.py` · **Table:** `findings`

A discovered vulnerability or security issue. Tracks triage lifecycle, evidence, and bounty info.

| Field                 | Type           | Notes                                       |
|-----------------------|----------------|---------------------------------------------|
| `scan_id`             | FK → scans     | `CASCADE` on delete, indexed                |
| `target_id`           | FK → targets   | `CASCADE` on delete, indexed                |
| `signature_id`        | FK → signatures| `SET NULL` on delete                        |
| `title`               | String(500)    | Not null                                    |
| `description`         | Text           |                                             |
| `severity`            | Enum           | `Severity`, indexed, defaults to `INFO`     |
| `status`              | Enum           | `FindingStatus`, defaults to `NEW`          |
| `cvss_score`          | String(10)     |                                             |
| `cve_id`              | String(50)     |                                             |
| `cwe_id`              | String(50)     |                                             |
| `evidence`            | JSON           | Default `{}`                                |
| `remediation`         | Text           |                                             |
| `affected_url`        | Text           |                                             |
| `affected_parameter`  | String(255)    |                                             |
| `poc`                 | Text           | Proof-of-concept                            |
| `is_duplicate`        | Boolean        | Default `False`                             |
| `duplicate_of_id`     | FK → findings  | Self-referential, `SET NULL` on delete      |
| `reported_at`         | DateTime       |                                             |
| `bounty_amount`       | Integer        |                                             |

**Relationships:** `scan`, `target`, `signature`

**Methods:** `mark_false_positive()`, `mark_reported()`.

### `Severity` enum
`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`

### `FindingStatus` enum
`NEW`, `TRIAGING`, `VALIDATED`, `REPORTED`, `ACCEPTED`, `RESOLVED`, `DUPLICATE`, `FALSE_POSITIVE`, `WONT_FIX`

---

## Module

**File:** `module.py` · **Table:** `modules`

A reusable scanner module — the building blocks of the scanning engine. Dynamically loaded by `python_class`.

| Field               | Type        | Notes                                       |
|---------------------|-------------|---------------------------------------------|
| `name`              | String(255) | Unique, indexed, not null                   |
| `display_name`      | String(255) | Not null                                    |
| `module_type`       | Enum        | `ModuleType`, not null                      |
| `version`           | String(50)  | Not null                                    |
| `description`       | Text        |                                             |
| `author`            | String(100) |                                             |
| `icon`              | String(50)  |                                             |
| `python_class`      | String(255) | Dotted path to implementation class         |
| `default_config`    | JSON        | Default `{}`                                |
| `required_config`   | JSON        | Default `[]`                                |
| `outputs`           | JSON        | Default `[]`                                |
| `dependencies`      | JSON        | Default `[]`                                |
| `tags`              | JSON        | Default `[]`                                |
| `is_active`         | Boolean     | Default `True`                              |
| `status`            | Enum        | `ModuleStatus`, defaults to `ACTIVE`        |
| `execution_count`   | Integer     | Default `0`                                 |
| `average_duration`  | Integer     | Default `0`                                 |
| `success_rate`      | Integer     | 0–100, default `100`                        |
| `documentation_url` | String(500) |                                             |

**Relationships:** `scans` (1→N)

**Methods:** `increment_execution()`, `activate()`, `deactivate()`, `record_execution(duration, success)` — running average duration + success rate.

### `ModuleType` enum
`RECONNAISSANCE`, `VULNERABILITY`, `EXPLOITATION`, `INTELLIGENCE`, `NETWORK`, `UTILITY`, `CUSTOM`, `WEB`

### `ModuleStatus` enum
`ACTIVE`, `INACTIVE`, `DEPRECATED`, `TESTING`

---

## Signature

**File:** `signature.py` · **Table:** `signatures`

User-editable detection signatures. Define **what** to look for and **how** to detect it. Created and managed from the dashboard.

| Field                 | Type        | Notes                                          |
|-----------------------|-------------|------------------------------------------------|
| `name`                | String(255) | Unique, indexed, not null                      |
| `signature_id`        | String(100) | Unique, indexed, not null                      |
| `signature_type`      | Enum        | `SignatureType`, not null                      |
| `version`             | String(50)  | Default `'1.0'`                                |
| `author`              | String(100) |                                                |
| `description`         | Text        |                                                |
| `icon`                | String(50)  |                                                |
| `severity`            | String(20)  | Default `'info'`                               |
| `language`            | Enum        | `SignatureLanguage`, defaults to `YAML`        |
| `template`            | Text        | The signature body, not null                   |
| `matchers`            | JSON        | Default `[]`                                   |
| `extractors`          | JSON        | Default `[]`                                   |
| `references`          | JSON        | Default `[]`                                   |
| `tags`                | JSON        | Default `[]`                                   |
| `cve_id`              | String(50)  |                                                |
| `cwe_id`              | String(50)  |                                                |
| `is_active`           | Boolean     | Indexed, default `True`                        |
| `is_verified`         | Boolean     | Default `False`                                |
| `false_positive_rate` | Integer     | Default `0`                                    |
| `execution_count`     | Integer     | Default `0`                                    |
| `success_count`       | Integer     | Default `0`                                    |
| `category`            | String(100) | Indexed                                        |
| `requires_auth`       | Boolean     | Default `False`                                |
| `signature_metadata`  | JSON        | Default `{}`                                   |

**Indexes:** `(signature_type, is_active)`

**Relationships:** `findings` (1→N)

**Methods:** `increment_execution()`, `increment_success()`, `activate()`, `deactivate()`, `success_rate` (computed property).

### `SignatureType` enum
`VULNERABILITY`, `CONFIGURATION`, `INFORMATION_DISCLOSURE`, `TECHNOLOGY_DETECTION`, `CUSTOM`

### `SignatureLanguage` enum
`YAML`, `JSON`

---

## Workflow

**File:** `workflow.py` · **Table:** `workflows`

Automated scan chains. Define multi-step scanning pipelines (e.g., Subdomain Enum → DNS Resolution → Port Scan → Vuln Scan).

| Field              | Type        | Notes                                  |
|--------------------|-------------|----------------------------------------|
| `name`             | String(255) | Unique, not null                       |
| `description`     | Text        |                                        |
| `vault_id`         | FK → vaults | `CASCADE` on delete                    |
| `steps`            | JSON        | Step graph definition, not null        |
| `triggers`         | JSON        | Default `[]`                           |
| `schedule`         | String(100) | Cron or similar                        |
| `is_active`        | Boolean     | Default `True`                         |
| `status`           | Enum        | `WorkflowStatus`, defaults to `DRAFT`  |
| `execution_count`  | Integer     | Default `0`                            |
| `last_executed_at` | DateTime    |                                        |

**Relationships:** `vault`

### `WorkflowStatus` enum
`DRAFT`, `ACTIVE`, `PAUSED`, `ARCHIVED`

---

## Note

**File:** `notes.py` · **Table:** `notes`

Free-form notes scoped to a Vault, a Target, or globally. Tag- and pin-aware.

| Field        | Type        | Notes                                |
|--------------|-------------|--------------------------------------|
| `title`      | String(255) |                                      |
| `content`    | Text        | Not null                             |
| `note_type`  | Enum        | `NoteType`, defaults to `GENERAL`    |
| `note_tags`  | JSON        | Default `[]`                         |
| `is_pinned`  | Boolean     | Default `False`                      |
| `vault_id`   | FK → vaults | `CASCADE` on delete                  |
| `target_id`  | FK → targets| `CASCADE` on delete                  |

**Relationships:** `vault`, `target`

**Methods:** `add_tag(tag)`, `remove_tag(tag)`, `context` (computed — `Target: …` / `Vault: …` / `Global`).

### `NoteType` enum
`GENERAL`, `FINDING`, `TODO`, `METHODOLOGY`, `PERSONAL`

---

## SystemConfig

**File:** `system_config.py` · **Table:** `system_configs`

Dynamic key/value configuration store with optional Fernet encryption (for API keys and secrets).

| Field           | Type        | Notes                                 |
|-----------------|-------------|---------------------------------------|
| `key`           | String(255) | Unique, indexed, not null             |
| `value`         | Text        | Not null (encrypted if flagged)       |
| `description`   | String(500) |                                       |
| `is_encrypted`  | Boolean     | Default `False`                       |
| `group`         | String(100) | Default `'general'`                   |
| `created_at`    | DateTime    | Server-set                            |
| `updated_at`    | DateTime    | Server-set, auto on update            |

**Methods:** `set_value(raw_value, encrypt=False)`, `get_value()` — transparent Fernet encryption/decryption.

> Not exported via `app/models/__init__.py`.

---

## Relationship Map

```
Vault ──┬── Target ──┬── Asset ── (self: parent/children)
        │            ├── Scan ── Finding
        │            ├── Note
        │            └── (self: parent/children)
        ├── Workflow
        └── Note

Module ── Scan
Signature ── Finding
SystemConfig (standalone)
```
