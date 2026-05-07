/**
 * Phantom Framework — mock fixtures.
 *
 * Mirrors the SQL models so the UI behaves like real data is in flight.
 * Replace this file with real API calls once the backend is wired up.
 */

import { ago } from '@/utils/time'
import type {
  Finding,
  ProxyEntry,
  ScanLine,
  SignatureTemplate,
  Target,
  Vault,
} from '@/types'

export const vaults: Vault[] = [
  {
    id: 1,
    name: 'Acme Corp',
    platform: 'HACKERONE',
    target_domain: 'acme.com',
    program_url: 'https://hackerone.com/acme',
    scope_rules: {
      in: ['*.acme.com', 'api.acme.io'],
      out: ['blog.acme.com', '*.staging.acme.com'],
    },
    stats: { targets: 47, findings: 23, critical: 2, high: 5, scans_running: 1 },
    last_activity: ago(8),
  },
  {
    id: 2,
    name: 'Northwind Systems',
    platform: 'BUGCROWD',
    target_domain: 'northwind.io',
    program_url: 'https://bugcrowd.com/northwind',
    scope_rules: {
      in: ['*.northwind.io', '*.nw-internal.com'],
      out: ['*.dev.northwind.io'],
    },
    stats: { targets: 128, findings: 61, critical: 4, high: 11, scans_running: 0 },
    last_activity: ago(72),
  },
  {
    id: 3,
    name: 'Helios Banking',
    platform: 'INTIGRITI',
    target_domain: 'heliosbank.eu',
    scope_rules: { in: ['*.heliosbank.eu'], out: [] },
    stats: { targets: 19, findings: 8, critical: 1, high: 2, scans_running: 0 },
    last_activity: ago(60 * 24 * 3),
  },
  {
    id: 4,
    name: 'Verdant Health',
    platform: 'YESWEHACK',
    target_domain: 'verdant.health',
    scope_rules: { in: ['*.verdant.health'], out: ['marketing.verdant.health'] },
    stats: { targets: 73, findings: 34, critical: 0, high: 8, scans_running: 2 },
    last_activity: ago(35),
  },
  {
    id: 5,
    name: 'Personal Research',
    platform: 'CUSTOM',
    target_domain: '—',
    scope_rules: { in: [], out: [] },
    stats: { targets: 12, findings: 4, critical: 0, high: 1, scans_running: 0 },
    last_activity: ago(60 * 24 * 12),
  },
]

export const targets: Target[] = [
  {
    id: 101,
    identifier: 'acme.com',
    target_type: 'WEB',
    status: 'ACTIVE',
    is_wildcard: false,
    ip_address: '34.117.65.4',
    tech_stack: ['nginx', 'React', 'Node.js'],
    risk_score: 42,
    last_scanned_at: ago(120),
    assets_count: 84,
    findings_count: 3,
  },
  {
    id: 102,
    identifier: '*.acme.com',
    target_type: 'WEB',
    status: 'ACTIVE',
    is_wildcard: true,
    ip_address: null,
    tech_stack: [],
    risk_score: 78,
    last_scanned_at: ago(35),
    assets_count: 312,
    findings_count: 12,
  },
  {
    id: 103,
    identifier: 'api.acme.io',
    target_type: 'API',
    status: 'VULNERABLE',
    is_wildcard: false,
    ip_address: '52.18.44.201',
    tech_stack: ['FastAPI', 'PostgreSQL', 'Redis'],
    risk_score: 91,
    last_scanned_at: ago(8),
    assets_count: 47,
    findings_count: 5,
  },
  {
    id: 104,
    identifier: 'admin.acme.com',
    target_type: 'WEB',
    status: 'ACTIVE',
    is_wildcard: false,
    ip_address: '34.117.65.7',
    tech_stack: ['Apache', 'PHP 7.4'],
    risk_score: 64,
    last_scanned_at: ago(180),
    assets_count: 23,
    findings_count: 2,
  },
  {
    id: 105,
    identifier: 'auth.acme.com',
    target_type: 'WEB',
    status: 'ACTIVE',
    is_wildcard: false,
    ip_address: '34.117.65.12',
    tech_stack: ['Auth0'],
    risk_score: 28,
    last_scanned_at: ago(60 * 6),
    assets_count: 9,
    findings_count: 0,
  },
  {
    id: 106,
    identifier: 'cdn.acme.com',
    target_type: 'WEB',
    status: 'ARCHIVED',
    is_wildcard: false,
    ip_address: null,
    tech_stack: ['Cloudflare'],
    risk_score: 12,
    last_scanned_at: ago(60 * 24 * 14),
    assets_count: 5,
    findings_count: 0,
  },
  {
    id: 107,
    identifier: 'mobile.acme.com',
    target_type: 'MOBILE',
    status: 'ACTIVE',
    is_wildcard: false,
    ip_address: '34.117.65.18',
    tech_stack: ['React Native'],
    risk_score: 51,
    last_scanned_at: ago(60 * 22),
    assets_count: 31,
    findings_count: 1,
  },
  {
    id: 108,
    identifier: 'staging-api.acme.com',
    target_type: 'API',
    status: 'BLACKLISTED',
    is_wildcard: false,
    ip_address: '10.0.4.18',
    tech_stack: [],
    risk_score: 0,
    last_scanned_at: null,
    assets_count: 0,
    findings_count: 0,
  },
]

export const findings: Finding[] = [
  {
    id: 5001,
    target_id: 103,
    scan_id: 9001,
    signature_id: 'sql-injection-error-based',
    title: 'Error-based SQL injection in /v2/users search',
    severity: 'CRITICAL',
    status: 'TRIAGING',
    cvss_score: '9.1',
    cve_id: null,
    cwe_id: 'CWE-89',
    affected_url: 'https://api.acme.io/v2/users?q=1%27',
    affected_parameter: 'q',
    description:
      "The 'q' parameter on /v2/users reflects database error messages when injected with a single quote. Detected via the sql-injection-error-based template; PostgreSQL error message visible in response body.",
    poc:
      "GET /v2/users?q=1' HTTP/1.1\nHost: api.acme.io\nAuthorization: Bearer <redacted>\n\n→ 500 Internal Server Error\n   Body contains: 'PostgreSQL ERROR: unterminated quoted string at or near \"1''\"'",
    remediation:
      'Use parameterized queries via SQLAlchemy core. Never interpolate user input into raw SQL.',
    created_at: ago(8),
    reported_at: null,
  },
  {
    id: 5002,
    target_id: 103,
    scan_id: 9001,
    signature_id: 'jwt-none-algorithm',
    title: 'JWT accepts "none" algorithm on /v2/auth/refresh',
    severity: 'CRITICAL',
    status: 'NEW',
    cvss_score: '9.8',
    cve_id: null,
    cwe_id: 'CWE-347',
    affected_url: 'https://api.acme.io/v2/auth/refresh',
    affected_parameter: 'Authorization',
    description:
      'The /v2/auth/refresh endpoint accepts JWTs signed with the "none" algorithm. Authentication bypass possible.',
    poc:
      'curl -H "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9." \\\n     https://api.acme.io/v2/auth/refresh\n→ 200 OK',
    remediation: 'Reject "none" algorithm explicitly. Pin allowed algorithms to a whitelist.',
    created_at: ago(35),
    reported_at: null,
  },
  {
    id: 5003,
    target_id: 102,
    scan_id: 9002,
    signature_id: 'reflected-xss',
    title: 'Reflected XSS in marketing landing search box',
    severity: 'HIGH',
    status: 'VALIDATED',
    cvss_score: '7.4',
    cwe_id: 'CWE-79',
    affected_url: 'https://landing.acme.com/search?q=<svg/onload=alert(1)>',
    affected_parameter: 'q',
    description:
      'The search field on landing pages does not encode user input before rendering it back into the page, allowing reflected XSS.',
    poc: 'https://landing.acme.com/search?q=<svg/onload=alert(document.domain)>',
    remediation: 'HTML-encode user input on render. Add a Content-Security-Policy header.',
    created_at: ago(180),
    reported_at: null,
  },
  {
    id: 5004,
    target_id: 104,
    scan_id: 9003,
    signature_id: 'admin-panel-finder',
    title: 'Exposed phpMyAdmin instance',
    severity: 'HIGH',
    status: 'REPORTED',
    cvss_score: '7.2',
    cwe_id: 'CWE-284',
    affected_url: 'https://admin.acme.com/phpmyadmin/',
    affected_parameter: null,
    description:
      'A phpMyAdmin login page is publicly accessible at /phpmyadmin/. While authentication is required, it provides an attack surface for credential stuffing and CVE exploitation.',
    poc: 'GET https://admin.acme.com/phpmyadmin/\n→ 200 OK\n   Title: phpMyAdmin 5.1.1',
    remediation: 'Restrict access via IP allowlist or remove phpMyAdmin from production.',
    created_at: ago(60 * 18),
    reported_at: ago(60 * 12),
    bounty_amount: 500,
  },
  {
    id: 5005,
    target_id: 103,
    scan_id: 9001,
    signature_id: 'api-key-exposure',
    title: 'AWS access key in /static/js/main.js',
    severity: 'HIGH',
    status: 'VALIDATED',
    cvss_score: '7.5',
    cwe_id: 'CWE-798',
    affected_url: 'https://api.acme.io/static/js/main.js',
    affected_parameter: null,
    description:
      'AWS access key (AKIA...) hardcoded in a public JavaScript bundle. Key permissions not yet enumerated.',
    poc: 'GET /static/js/main.js\n→ const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";',
    remediation:
      'Rotate the key immediately. Move secrets to environment variables and never bundle them client-side.',
    created_at: ago(60 * 4),
    reported_at: null,
  },
  {
    id: 5006,
    target_id: 102,
    scan_id: 9002,
    signature_id: 'open-redirect',
    title: 'Open redirect on /go endpoint',
    severity: 'MEDIUM',
    status: 'NEW',
    cvss_score: '5.4',
    cwe_id: 'CWE-601',
    affected_url: 'https://acme.com/go?url=https://evil.example',
    affected_parameter: 'url',
    description:
      '/go redirects to any user-supplied URL without validation. Can be used in phishing campaigns.',
    poc: 'GET https://acme.com/go?url=https://evil.example\n→ 302 Location: https://evil.example',
    remediation: 'Validate redirect targets against an allowlist of internal domains.',
    created_at: ago(60 * 9),
    reported_at: null,
  },
  {
    id: 5007,
    target_id: 102,
    scan_id: 9002,
    signature_id: 'cors-misconfiguration',
    title: 'CORS allows arbitrary origin with credentials',
    severity: 'MEDIUM',
    status: 'TRIAGING',
    cvss_score: '6.1',
    cwe_id: 'CWE-942',
    affected_url: 'https://api.acme.com/v1/me',
    affected_parameter: 'Origin',
    description:
      'Access-Control-Allow-Origin reflects any Origin header while Access-Control-Allow-Credentials is true.',
    poc:
      'curl -H "Origin: https://evil.example" https://api.acme.com/v1/me\n→ Access-Control-Allow-Origin: https://evil.example\n   Access-Control-Allow-Credentials: true',
    remediation: 'Pin allowed origins to a known allowlist. Never reflect arbitrary Origin values.',
    created_at: ago(60 * 14),
    reported_at: null,
  },
  {
    id: 5008,
    target_id: 102,
    scan_id: 9002,
    signature_id: 'directory-listing',
    title: 'Directory listing enabled on /backups/',
    severity: 'LOW',
    status: 'NEW',
    cvss_score: '3.7',
    cwe_id: 'CWE-548',
    affected_url: 'https://files.acme.com/backups/',
    affected_parameter: null,
    description: 'Apache directory listing enabled. Some backup files appear empty or zero-byte.',
    poc: 'GET https://files.acme.com/backups/\n→ 200 OK\n   <h1>Index of /backups</h1>',
    remediation: 'Disable Options Indexes in Apache config.',
    created_at: ago(60 * 26),
    reported_at: null,
  },
  {
    id: 5009,
    target_id: 101,
    scan_id: 9004,
    signature_id: 'security-headers',
    title: 'Missing Strict-Transport-Security header',
    severity: 'INFO',
    status: 'NEW',
    cvss_score: '0.0',
    cwe_id: 'CWE-319',
    affected_url: 'https://acme.com/',
    affected_parameter: null,
    description: 'HSTS header not set on root domain.',
    poc: 'curl -I https://acme.com/\n→ (no Strict-Transport-Security header in response)',
    remediation: 'Add: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload',
    created_at: ago(60 * 50),
    reported_at: null,
  },
  {
    id: 5010,
    target_id: 107,
    scan_id: 9005,
    signature_id: 'ssrf-detection',
    title: 'SSRF via image-proxy parameter',
    severity: 'CRITICAL',
    status: 'NEW',
    cvss_score: '9.0',
    cwe_id: 'CWE-918',
    affected_url:
      'https://mobile.acme.com/api/img?url=http://169.254.169.254/latest/meta-data/',
    affected_parameter: 'url',
    description:
      'The image-proxy endpoint fetches arbitrary user-supplied URLs server-side. AWS instance metadata is accessible.',
    poc:
      'GET /api/img?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/\n→ 200 OK with IAM role credentials in response',
    remediation:
      'Validate target URL against an allowlist. Block link-local and private IP ranges.',
    created_at: ago(22),
    reported_at: null,
  },
]

export const scanStream: ScanLine[] = [
  { ts: '14:02:18.041', level: 'info', text: 'phantom scan https://api.acme.io --templates injection,exposure -c 20' },
  { ts: '14:02:18.103', level: 'info', text: 'Loaded 26 templates · severity ≥ low · 4 categories' },
  { ts: '14:02:18.214', level: 'info', text: 'Connectivity check → 200 OK · 47ms · TLSv1.3' },
  { ts: '14:02:18.301', level: 'info', text: 'Crawler started · max-depth 5 · max-pages 100' },
  { ts: '14:02:19.842', level: 'info', text: 'Discovered 14 endpoints · 6 forms · 23 parameters' },
  { ts: '14:02:20.055', level: 'info', text: 'Running injection/sql/error-based.yaml on 23 parameters' },
  { ts: '14:02:21.488', level: 'critical', text: "MATCH · sql-injection-error-based · /v2/users?q=1' · group=error_message" },
  { ts: '14:02:21.491', level: 'info', text: '  └ extracted: "PostgreSQL ERROR: unterminated quoted string..."' },
  { ts: '14:02:22.014', level: 'info', text: 'Running injection/xss/reflected.yaml on 23 parameters' },
  { ts: '14:02:23.776', level: 'info', text: 'No matches in injection/xss/reflected.yaml' },
  { ts: '14:02:24.004', level: 'info', text: 'Running exposure/api-keys.yaml on 8 JS bundles' },
  { ts: '14:02:25.231', level: 'high', text: 'MATCH · api-key-exposure · /static/js/main.js · group=aws_key' },
  { ts: '14:02:25.234', level: 'info', text: '  └ extracted: AKIAIOSFODNN7EXAMPLE' },
  { ts: '14:02:25.890', level: 'info', text: 'Running exposure/jwt-none.yaml on /v2/auth/*' },
  { ts: '14:02:27.118', level: 'critical', text: 'MATCH · jwt-none-algorithm · /v2/auth/refresh' },
  { ts: '14:02:28.402', level: 'info', text: 'Running misconfiguration/cors.yaml' },
  { ts: '14:02:29.604', level: 'medium', text: 'MATCH · cors-misconfiguration · /v1/me · arbitrary origin reflected' },
  { ts: '14:02:30.122', level: 'info', text: 'Running redirect/open-redirect.yaml' },
  { ts: '14:02:31.450', level: 'info', text: 'No matches in redirect/open-redirect.yaml' },
  { ts: '14:02:31.778', level: 'info', text: '23/26 templates complete · 3 in progress' },
  { ts: '14:02:33.021', level: 'low', text: 'MATCH · directory-listing · /backups/' },
  { ts: '14:02:34.500', level: 'info', text: 'Scan complete · 4 findings · 16.4s · 247 requests' },
]

const PROXY_METHODS: Array<ProxyEntry['method']> = [
  'GET', 'GET', 'GET', 'POST', 'GET', 'OPTIONS', 'POST', 'GET', 'PUT', 'GET', 'GET', 'DELETE',
]
const PROXY_HOSTS = [
  'api.acme.io', 'acme.com', 'cdn.acme.com', 'auth.acme.com', 'api.acme.io', 'api.acme.io',
]
const PROXY_PATHS = [
  '/v2/users?q=admin', '/', '/static/js/main.js', '/v2/auth/login', '/v2/sessions/current',
  '/v2/users/12/orders', '/v2/billing/charge', '/static/css/app.css', '/v2/users/12',
  '/healthz', '/v1/me', '/v2/sessions/abc-123',
]
const PROXY_STATUSES = [200, 200, 200, 201, 200, 204, 200, 200, 200, 200, 401, 200, 500, 304, 403, 200]

function buildProxyTraffic(): ProxyEntry[] {
  const out: ProxyEntry[] = []
  let t = 0
  for (let i = 0; i < 24; i++) {
    const m = PROXY_METHODS[i % PROXY_METHODS.length]!
    const h = PROXY_HOSTS[i % PROXY_HOSTS.length]!
    const p = PROXY_PATHS[i % PROXY_PATHS.length]!
    const s = PROXY_STATUSES[i % PROXY_STATUSES.length]!
    const dur = Math.round(20 + Math.random() * 380)
    t += Math.round(40 + Math.random() * 400)
    const mime = p.endsWith('.js')
      ? 'application/javascript'
      : p.endsWith('.css')
        ? 'text/css'
        : p.includes('/v')
          ? 'application/json'
          : 'text/html'
    out.push({
      id: 7000 + i,
      ts: t,
      method: m,
      host: h,
      path: p,
      status: s,
      size: Math.round(120 + Math.random() * 14000),
      dur,
      mime,
      is_https: !p.includes('healthz'),
      intercepted: i === 3 || i === 10,
    })
  }
  return out
}

export const proxyTraffic: ProxyEntry[] = buildProxyTraffic()

export const templates: SignatureTemplate[] = [
  { id: 't01', signature_id: 'sql-injection-error-based', name: 'SQL Injection — Error Based', severity: 'critical', category: 'injection', tags: ['sqli', 'database'], is_active: true, execution_count: 1284, success_count: 47, version: '1.4', author: 'phantom-team' },
  { id: 't02', signature_id: 'reflected-xss', name: 'Reflected Cross-Site Scripting', severity: 'high', category: 'injection', tags: ['xss', 'client-side'], is_active: true, execution_count: 982, success_count: 31, version: '1.2', author: 'phantom-team' },
  { id: 't03', signature_id: 'jwt-none-algorithm', name: 'JWT "none" Algorithm Acceptance', severity: 'critical', category: 'authentication', tags: ['jwt', 'auth-bypass'], is_active: true, execution_count: 412, success_count: 8, version: '1.0', author: 'kuduxaaa' },
  { id: 't04', signature_id: 'admin-panel-finder', name: 'Admin Panel Discovery', severity: 'low', category: 'exposure', tags: ['panel', 'admin'], is_active: true, execution_count: 3201, success_count: 156, version: '1.5', author: 'phantom-team' },
  { id: 't05', signature_id: 'api-key-exposure', name: 'Exposed API Keys', severity: 'high', category: 'exposure', tags: ['api-key', 'secret'], is_active: true, execution_count: 2104, success_count: 89, version: '1.3', author: 'phantom-team' },
  { id: 't06', signature_id: 'open-redirect', name: 'Open Redirect Vulnerability', severity: 'medium', category: 'redirect', tags: ['redirect', 'phishing'], is_active: true, execution_count: 1567, success_count: 23, version: '1.1', author: 'phantom-team' },
  { id: 't07', signature_id: 'ssrf-detection', name: 'Server-Side Request Forgery', severity: 'critical', category: 'ssrf', tags: ['ssrf', 'server-side'], is_active: true, execution_count: 743, success_count: 12, version: '1.2', author: 'phantom-team' },
  { id: 't08', signature_id: 'path-traversal', name: 'Path Traversal / LFI', severity: 'high', category: 'injection', tags: ['lfi', 'traversal'], is_active: true, execution_count: 891, success_count: 19, version: '1.1', author: 'phantom-team' },
  { id: 't09', signature_id: 'cors-misconfiguration', name: 'CORS Misconfiguration', severity: 'medium', category: 'misconfiguration', tags: ['cors', 'header'], is_active: true, execution_count: 1421, success_count: 34, version: '1.0', author: 'phantom-team' },
  { id: 't10', signature_id: 'directory-listing', name: 'Directory Listing Enabled', severity: 'low', category: 'misconfiguration', tags: ['exposure', 'apache'], is_active: true, execution_count: 2890, success_count: 71, version: '1.0', author: 'phantom-team' },
  { id: 't11', signature_id: 'security-headers', name: 'Missing Security Headers', severity: 'info', category: 'misconfiguration', tags: ['headers'], is_active: true, execution_count: 4012, success_count: 312, version: '1.2', author: 'phantom-team' },
  { id: 't12', signature_id: 'ssti-detection', name: 'Server-Side Template Injection', severity: 'critical', category: 'injection', tags: ['ssti'], is_active: false, execution_count: 233, success_count: 4, version: '0.9', author: 'community' },
]

export const templateYaml = `id: sql-injection-error-based
name: SQL Injection — Error Based
author: phantom-team
severity: critical
description: |
  Detects SQL injection by injecting a single quote and
  matching common database error messages in the response.

tags:
  - sqli
  - injection
  - database

info:
  cwe-id: CWE-89
  cvss-score: 9.1

requests:
  - method: GET
    path:
      - "{{BaseURL}}/{{path}}?{{param}}={{payload}}"

    attack: batteringram
    payloads:
      payload:
        - "1'"
        - "1\\""
        - "1') --"
        - "1' OR '1'='1"

    matchers-condition: and
    matchers:
      - type: word
        words: ["Adminer"]
        negative: true

      - type: regex
        regex:
          - "SQL syntax.*MySQL"
          - "Warning.*mysqli?"
          - "PostgreSQL.*ERROR"
          - "ORA-[0-9]{5}"
        condition: or

    extractors:
      - type: regex
        name: error_message
        group: 1
        regex:
          - "(SQL syntax[^<]+)"
          - "(PostgreSQL ERROR[^<]+)"
`
