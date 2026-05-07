/**
 * Phantom Framework — Domain types.
 *
 * Mirrors the backend SQL models so the frontend speaks the same language as the API.
 */

export type PlatformType = 'HACKERONE' | 'BUGCROWD' | 'INTIGRITI' | 'YESWEHACK' | 'CUSTOM'

export type TargetType = 'WEB' | 'API' | 'MOBILE' | 'NETWORK' | 'CLOUD' | 'OTHER'

export type TargetStatus = 'ACTIVE' | 'ARCHIVED' | 'BLACKLISTED' | 'VULNERABLE'

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'

export type FindingStatus =
  | 'NEW'
  | 'TRIAGING'
  | 'VALIDATED'
  | 'REPORTED'
  | 'ACCEPTED'
  | 'RESOLVED'
  | 'DUPLICATE'
  | 'FALSE_POSITIVE'
  | 'WONT_FIX'

export type ScanType =
  | 'SUBDOMAIN_ENUM'
  | 'JAVASCRIPT_ANALYSIS'
  | 'SERVICE_DETECTION'
  | 'DNS_RESOLUTION'
  | 'PORT_SCAN'
  | 'WEB_CRAWL'
  | 'TECHNOLOGY_DETECTION'
  | 'SSL_ANALYSIS'
  | 'VULNERABILITY_SCAN'
  | 'CUSTOM_SIGNATURE'
  | 'FULL_RECON'

export type ScanStatus = 'QUEUED' | 'RUNNING' | 'PAUSED' | 'COMPLETED' | 'CANCELLED' | 'FAILED'

export type AssetStatus = 'NEW' | 'VERIFIED' | 'CHANGED' | 'REMOVED' | 'MONITORED'

export type ScanLineLevel = 'info' | 'critical' | 'high' | 'medium' | 'low'

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'OPTIONS' | 'HEAD'

export interface ScopeRules {
  in: string[]
  out: string[]
}

export interface VaultStats {
  targets: number
  findings: number
  critical: number
  high: number
  scans_running: number
}

export interface Vault {
  id: number
  name: string
  platform: PlatformType
  target_domain: string
  program_url?: string
  scope_rules: ScopeRules
  stats: VaultStats
  last_activity: Date
}

export interface Target {
  id: number
  identifier: string
  target_type: TargetType
  status: TargetStatus
  is_wildcard: boolean
  ip_address: string | null
  tech_stack: string[]
  risk_score: number
  last_scanned_at: Date | null
  assets_count: number
  findings_count: number
}

export interface Finding {
  id: number
  target_id: number
  scan_id: number
  signature_id: string
  title: string
  severity: Severity
  status: FindingStatus
  cvss_score: string
  cve_id?: string | null
  cwe_id?: string | null
  affected_url: string
  affected_parameter: string | null
  description: string
  poc: string
  remediation: string
  created_at: Date
  reported_at?: Date | null
  bounty_amount?: number
}

export interface ScanLine {
  ts: string
  level: ScanLineLevel
  text: string
}

export interface ProxyEntry {
  id: number
  ts: number
  method: HttpMethod
  host: string
  path: string
  status: number
  size: number
  dur: number
  mime: string
  is_https: boolean
  intercepted: boolean
}

export interface SignatureTemplate {
  id: string
  signature_id: string
  name: string
  severity: Lowercase<Severity>
  category: string
  tags: string[]
  is_active: boolean
  execution_count: number
  success_count: number
  version: string
  author: string
}

export type ViewKey =
  | 'vaults'
  | 'targets'
  | 'findings'
  | 'scans'
  | 'signatures'
  | 'proxy'
  | 'workflows'
  | 'notes'
