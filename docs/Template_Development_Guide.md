# 📚 Phantom Framework - Complete Template Development Guide

**Version:** 1.0  
**Last Updated:** January 12, 2026  
**Author:** Kuduxaaa

---

## 🎯 Table of Contents

1. [Introduction](#-introduction)
2. [Template Basics](#-template-basics)
3. [Template Structure](#-template-structure)
4. [Request Configuration](#-request-configuration)
5. [Matchers - Detection Logic](#-matchers)
6. [Extractors - Data Extraction](#-extractors)
7. [Variables & DSL](#-variables-dsl)
8. [Advanced Features](#-advanced-features)
9. [Complete Examples](#-complete-examples)
10. [Best Practices](#-best-practices)
11. [Troubleshooting](#-troubleshooting)

---

## 📖 Introduction

### What are Phantom Templates?

Phantom templates are **YAML or JSON files** that define:
- **WHAT** vulnerability to look for
- **HOW** to detect it (matchers)
- **WHERE** to extract data from responses (extractors)
- **WHEN** to consider something a vulnerability

Think of templates as **recipes for finding security issues**. Just like a cooking recipe tells you ingredients and steps, a template tells Phantom:
- Which URLs to test
- What HTTP requests to send
- What responses indicate a vulnerability

### Why Use Templates?

✅ **Reusable**: Write once, scan thousands of targets  
✅ **Shareable**: Exchange templates with other hunters  
✅ **Declarative**: No coding needed, just describe what you want  
✅ **Powerful**: Supports complex multi-step attacks  

---

## 🏗️ Template Basics

### Your First Template (Hello World)

```yaml
# Simplest possible template
id: hello-phantom
name: My First Template
severity: info

requests:
  - method: GET
    path:
      - "/"
    
    matchers:
      - type: word
        words:
          - "Welcome"
```

**What this does:**
1. Sends `GET` request to `/`
2. Checks if response contains word "Welcome"
3. If yes → **MATCH** (vulnerability found)
4. If no → No match

### Running This Template

```python
from app.core.scanners.signature_scanner import SignatureScanner

scanner = SignatureScanner()
result = await scanner.scan_with_yaml(template_yaml, "https://example.com")

if result['matched']:
    print("Found vulnerability!")
```

---

## 📋 Template Structure

### Required Fields

Every template **MUST** have these fields:

```yaml
id: unique-template-identifier        # Unique ID (no spaces)
name: Human Readable Template Name    # Descriptive name
```

### Optional but Recommended Fields

```yaml
severity: critical                    # info, low, medium, high, critical
author: YourName                      # Who created this
description: What this template does  # Detailed explanation
tags:                                 # Categories
  - sqli
  - authentication
  - critical
references:                           # External links
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1234
version: 1.0                         # Template version
```

### Full Template Skeleton

```yaml
id: template-id
name: Template Name
version: 1.0
author: Your Name
severity: medium
description: Detailed description of what this detects

info:
  cve-id: CVE-2024-XXXX              # If applicable
  cwe-id: CWE-89                     # Weakness type
  cvss-score: 7.5                    # CVSS score
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
  remediation: How to fix this issue

tags:
  - category1
  - category2

references:
  - https://reference-link.com

variables:                            # Custom variables
  key: value

requests:                             # HTTP requests to send
  - method: GET
    path:
      - "/path"
    
    matchers:                         # Detection logic
      - type: word
        words:
          - "error"
    
    extractors:                       # Data extraction
      - type: regex
        regex:
          - 'pattern'

matchers-condition: or                # How to combine matchers (and/or)
stop-at-first-match: false           # Stop after first match?
```

---

## 🌐 Request Configuration

### Basic HTTP Request

```yaml
requests:
  - method: GET                       # HTTP method
    path:
      - "/api/users"                  # Path to test
```

**Supported Methods:**
- `GET` - Retrieve data
- `POST` - Submit data
- `PUT` - Update resource
- `DELETE` - Delete resource
- `PATCH` - Partial update
- `HEAD` - Headers only
- `OPTIONS` - Available methods

### Multiple Paths

Test multiple endpoints in one template:

```yaml
requests:
  - method: GET
    path:
      - "/admin"
      - "/administrator"
      - "/wp-admin"
      - "/phpmyadmin"
```

Phantom will test **each path** and report matches.

### Custom Headers

```yaml
requests:
  - method: GET
    path:
      - "/api/data"
    
    headers:
      Authorization: "Bearer {{token}}"
      X-Custom-Header: "value"
      User-Agent: "PhantomScanner/1.0"
```

### Request Body (POST/PUT)

```yaml
requests:
  - method: POST
    path:
      - "/login"
    
    headers:
      Content-Type: "application/json"
    
    body: |
      {
        "username": "admin",
        "password": "{{password}}"
      }
```

### Raw HTTP Request

For full control, use **raw HTTP**:

```yaml
requests:
  - raw:
      - |
        GET /api/users HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Custom-Agent
        Accept: application/json
        
      - |
        POST /login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded
        Content-Length: 27
        
        username=admin&password=test
```

**Use raw requests when:**
- You need exact control over HTTP format
- Testing protocol-level issues
- Sending malformed requests

### Redirects

```yaml
requests:
  - method: GET
    path:
      - "/redirect"
    
    redirects: true                   # Follow redirects (default: false)
    max-redirects: 5                  # Max redirect hops (default: 10)
```

### Cookie Reuse

```yaml
requests:
  - method: GET
    path:
      - "/login"
    cookie-reuse: true                # Reuse cookies from previous requests
```

---

## 🎯 Matchers - Detection Logic

Matchers define **WHEN** Phantom considers something a vulnerability.

### 1. Word Matcher

**Find exact words/phrases in response:**

```yaml
matchers:
  - type: word
    words:
      - "SQL syntax error"
      - "mysql_fetch_array()"
      - "You have an error in your SQL syntax"
```

**Case Insensitive:**

```yaml
matchers:
  - type: word
    words:
      - "error"
      - "warning"
    case-insensitive: true            # Matches "ERROR", "Error", "error"
```

**Match ALL words (AND logic):**

```yaml
matchers:
  - type: word
    words:
      - "admin"
      - "dashboard"
    condition: and                    # Must contain BOTH words
```

**Match ANY word (OR logic):**

```yaml
matchers:
  - type: word
    words:
      - "error"
      - "exception"
    condition: or                     # Matches if ANY word found (default)
```

### 2. Regex Matcher

**Use regular expressions for complex patterns:**

```yaml
matchers:
  - type: regex
    regex:
      - 'root:.*:0:0:'                           # /etc/passwd pattern
      - '\b(?:\d{1,3}\.){3}\d{1,3}\b'          # IP address
      - 'AKIA[0-9A-Z]{16}'                      # AWS Access Key
```

**Multiple Patterns:**

```yaml
matchers:
  - type: regex
    regex:
      - 'error:.*line \d+'
      - 'exception in.*at line'
    condition: or                     # Match ANY pattern
```

### 3. Status Code Matcher

**Match HTTP status codes:**

```yaml
matchers:
  - type: status
    status:
      - 200                           # OK
      - 201                           # Created
      - 204                           # No Content
```

**Common use cases:**

```yaml
# Check for successful authentication
matchers:
  - type: status
    status:
      - 200
      - 302                           # Redirect (often after login)

# Check for errors
matchers:
  - type: status
    status:
      - 500                           # Internal Server Error
      - 502                           # Bad Gateway
      - 503                           # Service Unavailable
```

### 4. Size Matcher

**Match response by content length:**

```yaml
matchers:
  - type: size
    size:
      - 1234                          # Exact size in bytes
      - 5000
```

**Use case - Detect empty responses:**

```yaml
matchers:
  - type: size
    size:
      - 0                             # Empty response
```

### 5. Binary Matcher

**Match binary patterns (hex):**

```yaml
matchers:
  - type: binary
    binary:
      - "504B0304"                    # ZIP file magic bytes
      - "89504E47"                    # PNG file magic bytes
      - "FFD8FF"                      # JPEG file magic bytes
```

### 6. DSL Matcher

**Use Domain Specific Language for complex logic:**

```yaml
matchers:
  - type: dsl
    dsl:
      - "status_code == 200"
      - "len(body) > 1000"
      - "contains(body, 'admin')"
```

**DSL Operators:**

| Operator | Meaning | Example |
|----------|---------|---------|
| `==` | Equal | `status_code == 200` |
| `!=` | Not equal | `status_code != 404` |
| `>` | Greater than | `len(body) > 5000` |
| `<` | Less than | `len(body) < 100` |
| `>=` | Greater or equal | `status_code >= 200` |
| `<=` | Less or equal | `status_code <= 299` |
| `contains` | String contains | `contains(body, 'error')` |

### Combining Multiple Matchers

**AND Logic (ALL must match):**

```yaml
matchers-condition: and               # ALL matchers must match
matchers:
  - type: status
    status:
      - 200
  
  - type: word
    words:
      - "admin"
  
  - type: regex
    regex:
      - 'version: \d+\.\d+\.\d+'
```

**OR Logic (ANY can match):**

```yaml
matchers-condition: or                # ANY matcher can match (default)
matchers:
  - type: status
    status:
      - 500
  
  - type: word
    words:
      - "error"
      - "exception"
```

### Negative Matchers

**Match when condition is NOT met:**

```yaml
matchers:
  - type: word
    words:
      - "Adminer"                     # Don't match if "Adminer" is found
    negative: true                    # Inverts the result
```

### Matcher Parts

**Specify WHERE to look for matches:**

```yaml
matchers:
  - type: word
    part: body                        # Search in response body (default)
    words:
      - "error"
  
  - type: word
    part: header                      # Search in response headers
    words:
      - "X-Powered-By: PHP"
```

**Available Parts:**

- `body` - Response body (default)
- `header` - Response headers
- `all` - Headers + Body
- `raw` - Raw HTTP response
- `request` - Original request
- `response` - Response data

---

## 🔍 Extractors - Data Extraction

Extractors **pull data** from responses (API keys, tokens, emails, etc.)

### 1. Regex Extractor

**Extract using regular expressions:**

```yaml
extractors:
  - type: regex
    name: api_key                     # Name for extracted data
    regex:
      - 'api_key["\s:]+([a-zA-Z0-9_-]+)'
    group: 1                          # Capture group to extract (default: 1)
```

**Multiple Patterns:**

```yaml
extractors:
  - type: regex
    name: emails
    regex:
      - '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
      - '\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b'
```

**Capture Groups:**

```yaml
extractors:
  - type: regex
    name: version
    regex:
      - 'Version: (\d+)\.(\d+)\.(\d+)'
    group: 0                          # 0 = entire match
                                      # 1 = first group (\d+)
                                      # 2 = second group (\d+)
                                      # 3 = third group (\d+)
```

### 2. Key-Value (kval) Extractor

**Extract HTTP header values:**

```yaml
extractors:
  - type: kval
    name: server_info
    kval:
      - "Server"                      # Extract "Server" header
      - "X-Powered-By"                # Extract "X-Powered-By" header
      - "X-Frame-Options"
```

**Example Output:**
```json
{
  "server_info": [
    "nginx/1.18.0",
    "PHP/7.4.3",
    "DENY"
  ]
}
```

### 3. JSON Extractor

**Extract from JSON responses:**

```yaml
extractors:
  - type: json
    name: user_data
    json:
      - "user.id"                     # Dot notation
      - "data.0.name"                 # Array index
      - "response.token"
```

**Example Response:**
```json
{
  "user": {
    "id": 123,
    "name": "John"
  },
  "data": [
    {"name": "First Item"}
  ],
  "response": {
    "token": "abc123"
  }
}
```

**Extracted:**
```json
{
  "user_data": ["123", "First Item", "abc123"]
}
```

### 4. XPath Extractor

**Extract from HTML/XML:**

```yaml
extractors:
  - type: xpath
    name: page_title
    xpath:
      - "//title/text()"              # Get <title> text
      - "//meta[@name='description']/@content"  # Get meta description
      - "//a/@href"                   # Get all links
```

### 5. DSL Extractor

**Use DSL functions to extract:**

```yaml
extractors:
  - type: dsl
    name: encoded_data
    dsl:
      - "base64_decode(body)"
      - "to_upper(body)"
      - "md5(body)"
```

### Internal Extractors

**Extract data to use in next request:**

```yaml
requests:
  # Request 1: Login and get token
  - method: POST
    path:
      - "/login"
    body: '{"username":"admin","password":"test"}'
    
    extractors:
      - type: json
        name: auth_token
        internal: true                # Don't show in results, use internally
        json:
          - "token"
  
  # Request 2: Use extracted token
  - method: GET
    path:
      - "/api/data"
    headers:
      Authorization: "Bearer {{auth_token}}"
```

---

## 🔧 Variables & DSL

### Variables

**Define reusable values:**

```yaml
variables:
  username: admin
  password: password123
  domain: example.com

requests:
  - method: POST
    path:
      - "/login"
    body: |
      {
        "user": "{{username}}",
        "pass": "{{password}}"
      }
```

### Built-in Context Variables

Phantom automatically provides these variables:

```yaml
{{BaseURL}}      # Full target URL (https://example.com)
{{Hostname}}     # Hostname only (example.com)
{{Host}}         # Host with port (example.com:443)
{{Port}}         # Port number (443)
{{Path}}         # URL path (/api/users)
{{Scheme}}       # Protocol (https)
{{RootURL}}      # Root URL (https://example.com)
```

**Example:**

```yaml
requests:
  - raw:
      - |
        GET /api/users HTTP/1.1
        Host: {{Hostname}}
        Referer: {{BaseURL}}
```

### DSL Functions

**String Functions:**

```yaml
{{to_lower("TEXT")}}              # Convert to lowercase → "text"
{{to_upper("text")}}              # Convert to uppercase → "TEXT"
{{trim("  text  ")}}              # Remove whitespace → "text"
{{len("hello")}}                  # String length → 5
{{reverse("hello")}}              # Reverse → "olleh"
{{repeat("x", 5)}}                # Repeat → "xxxxx"
{{replace("hello", "l", "L")}}    # Replace → "heLLo"
{{substr("hello", 0, 2)}}         # Substring → "he"
```

**Encoding Functions:**

```yaml
{{base64("text")}}                # Base64 encode → "dGV4dA=="
{{base64_decode("dGV4dA==")}}     # Base64 decode → "text"
{{url_encode("hello world")}}     # URL encode → "hello%20world"
{{url_decode("hello%20world")}}   # URL decode → "hello world"
{{hex_encode("abc")}}             # Hex encode → "616263"
{{hex_decode("616263")}}          # Hex decode → "abc"
```

**Hashing Functions:**

```yaml
{{md5("text")}}                   # MD5 hash
{{sha1("text")}}                  # SHA1 hash
{{sha256("text")}}                # SHA256 hash
{{hmac("text", "key", "sha256")}} # HMAC-SHA256
```

**Random Functions:**

```yaml
{{rand_int(1, 100)}}              # Random integer between 1-100
{{rand_text_alphanumeric(10)}}   # Random alphanumeric (aB3xY9kL2p)
{{rand_text_alpha(5)}}            # Random letters (aBxYz)
{{rand_text_numeric(6)}}          # Random numbers (123456)
```

**Example Usage:**

```yaml
requests:
  - method: POST
    path:
      - "/api/upload"
    
    headers:
      X-Request-ID: "{{rand_text_alphanumeric(16)}}"
    
    body: |
      {
        "filename": "test_{{rand_int(1000, 9999)}}.txt",
        "data": "{{base64(file_content)}}"
      }
```

---

## 🚀 Advanced Features

### 1. Payload Attacks

**Batteringram Attack** (Same payload for all placeholders):

```yaml
requests:
  - method: GET
    path:
      - "/search?q={{payload}}&category={{payload}}"
    
    attack: batteringram
    payloads:
      payload:
        - "admin"
        - "' OR '1'='1"
        - "<script>alert(1)</script>"
```

**Sends:**
- `/search?q=admin&category=admin`
- `/search?q=' OR '1'='1&category=' OR '1'='1`
- `/search?q=<script>alert(1)</script>&category=<script>alert(1)</script>`

**Pitchfork Attack** (Parallel payloads):

```yaml
requests:
  - method: POST
    path:
      - "/login"
    
    body: '{"user":"{{username}}","pass":"{{password}}"}'
    
    attack: pitchfork
    payloads:
      username:
        - "admin"
        - "root"
        - "user"
      password:
        - "admin123"
        - "root123"
        - "user123"
```

**Sends:**
- `admin:admin123`
- `root:root123`
- `user:user123`

**Clusterbomb Attack** (All combinations):

```yaml
requests:
  - method: POST
    path:
      - "/login"
    
    body: '{"user":"{{username}}","pass":"{{password}}"}'
    
    attack: clusterbomb
    payloads:
      username:
        - "admin"
        - "root"
      password:
        - "password"
        - "123456"
```

**Sends all combinations:**
- `admin:password`
- `admin:123456`
- `root:password`
- `root:123456`

### 2. Multi-Step Request Chains

**Login → Extract Token → Use Token:**

```yaml
requests:
  # Step 1: Login
  - method: POST
    path:
      - "/api/login"
    
    body: '{"username":"admin","password":"test"}'
    
    matchers:
      - type: status
        status:
          - 200
    
    extractors:
      - type: json
        name: token
        internal: true              # Use in next request
        json:
          - "access_token"
  
  # Step 2: Use token to access protected endpoint
  - method: GET
    path:
      - "/api/admin/users"
    
    headers:
      Authorization: "Bearer {{token}}"
    
    matchers:
      - type: status
        status:
          - 200
      
      - type: word
        words:
          - "users"
```

### 3. Request Conditions

**Execute request only if previous succeeded:**

```yaml
requests:
  # Request 1
  - method: GET
    path:
      - "/check"
    
    matchers:
      - type: status
        status:
          - 200
  
  # Request 2: Only runs if Request 1 matched
  - method: GET
    path:
      - "/exploit"
    
    req-condition: true             # Only run if previous request matched
```

### 4. Stop on First Match

**Stop scanning after first vulnerability found:**

```yaml
stop-at-first-match: true           # Stop after ANY request matches

requests:
  - method: GET
    path:
      - "/admin"
      - "/administrator"
      - "/wp-admin"
    
    stop-at-first-match: true       # Stop after first path matches
```

---

## 📚 Complete Examples

### Example 1: SQL Injection Detection

```yaml
id: sql-injection-error-based
name: SQL Injection - Error Based
author: Phantom Team
severity: critical
description: Detects SQL injection via error messages

tags:
  - sqli
  - injection
  - database

requests:
  - method: GET
    path:
      - "/product.php?id=1'"
      - "/user.php?id=1'"
      - "/article.php?id=1'"
    
    matchers-condition: and
    matchers:
      # Must NOT be Adminer (SQL admin tool)
      - type: word
        words:
          - "Adminer"
        negative: true
      
      # Must have SQL error
      - type: regex
        regex:
          - "SQL syntax.*MySQL"
          - "Warning.*mysqli?"
          - "MySQLSyntaxErrorException"
          - "PostgreSQL.*ERROR"
          - "ORA-[0-9]{5}"
        condition: or
    
    extractors:
      - type: regex
        name: error_message
        regex:
          - "(SQL syntax[^<]+)"
          - "(Warning[^<]+)"
        group: 1
```

### Example 2: Admin Panel Finder

```yaml
id: admin-panel-finder
name: Admin Panel Discovery
author: Phantom Team
severity: low
description: Finds exposed admin panels

tags:
  - panel
  - admin
  - exposure

requests:
  - method: GET
    path:
      - "/admin"
      - "/admin.php"
      - "/administrator"
      - "/wp-admin"
      - "/cpanel"
      - "/phpmyadmin"
      - "/admincp"
      - "/admin/login"
      - "/admin/index.php"
      - "/backend"
      - "/dashboard"
    
    matchers:
      - type: status
        status:
          - 200
      
      - type: word
        words:
          - "admin"
          - "login"
          - "dashboard"
          - "control panel"
        condition: or
        case-insensitive: true
    
    extractors:
      - type: regex
        name: title
        regex:
          - '<title>([^<]+)</title>'
        group: 1
```

### Example 3: API Key Exposure

```yaml
id: api-key-exposure
name: Exposed API Keys
author: Phantom Team
severity: high
description: Detects exposed API keys in JavaScript files

tags:
  - api-key
  - secret
  - exposure

requests:
  - method: GET
    path:
      - "/js/config.js"
      - "/static/js/main.js"
      - "/app.js"
      - "/bundle.js"
    
    matchers:
      - type: regex
        regex:
          - 'AKIA[0-9A-Z]{16}'                    # AWS Access Key
          - 'api[_-]?key["\s:=]+[a-zA-Z0-9_-]+'  # Generic API key
          - 'sk_live_[a-zA-Z0-9]{24,}'           # Stripe Live Key
          - 'AIza[0-9A-Za-z_-]{35}'              # Google API Key
        condition: or
    
    extractors:
      - type: regex
        name: aws_key
        regex:
          - '(AKIA[0-9A-Z]{16})'
        group: 1
      
      - type: regex
        name: api_key
        regex:
          - 'api[_-]?key["\s:=]+([a-zA-Z0-9_-]+)'
        group: 1
```

### Example 4: JWT Token Extractor

```yaml
id: jwt-token-extraction
name: JWT Token Extraction
author: Phantom Team
severity: medium
description: Extracts and analyzes JWT tokens

tags:
  - jwt
  - token
  - authentication

requests:
  - method: POST
    path:
      - "/api/login"
    
    headers:
      Content-Type: "application/json"
    
    body: |
      {
        "username": "test@example.com",
        "password": "password123"
      }
    
    matchers:
      - type: status
        status:
          - 200
      
      - type: word
        words:
          - "token"
          - "jwt"
    
    extractors:
      - type: regex
        name: jwt_token
        regex:
          - 'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
        group: 0
      
      - type: json
        name: token_from_json
        json:
          - "access_token"
          - "token"
          - "jwt"
```

### Example 5: XSS Detection

```yaml
id: reflected-xss
name: Reflected Cross-Site Scripting
author: Phantom Team
severity: medium
description: Detects reflected XSS vulnerabilities

tags:
  - xss
  - injection
  - client-side

requests:
  - method: GET
    path:
      - "/search?q={{payload}}"
      - "/page?name={{payload}}"
      - "/user?id={{payload}}"
    
    attack: batteringram
    payloads:
      payload:
        - "<script>alert(1)</script>"
        - "<img src=x onerror=alert(1)>"
        - "<svg onload=alert(1)>"
        - "javascript:alert(1)"
        - '"><script>alert(1)</script>'
    
    matchers:
      - type: word
        part: body
        words:
          - "<script>alert(1)</script>"
          - "<img src=x onerror=alert(1)>"
          - "<svg onload=alert(1)>"
        condition: or
```

### Example 6: SSRF Detection

```yaml
id: ssrf-detection
name: Server-Side Request Forgery
author: Phantom Team
severity: high
description: Detects SSRF vulnerabilities

tags:
  - ssrf
  - injection
  - server-side

variables:
  collaborator: "your-server.com"  # Your callback server

requests:
  - method: GET
    path:
      - "/fetch?url={{payload}}"
      - "/proxy?url={{payload}}"
      - "/download?file={{payload}}"
    
    attack: batteringram
    payloads:
      payload:
        - "http://{{collaborator}}/ssrf-test"
        - "http://169.254.169.254/latest/meta-data/"  # AWS metadata
        - "http://localhost:80"
        - "file:///etc/passwd"
    
    matchers:
      - type: word
        words:
          - "ami-"                    # AWS AMI ID
          - "root:x:0:0"             # /etc/passwd
        condition: or
      
      - type: regex
        regex:
          - 'instance-id.*i-[a-z0-9]+'
```

### Example 7: Open Redirect

```yaml
id: open-redirect
name: Open Redirect Vulnerability
author: Phantom Team
severity: low
description: Detects open redirect vulnerabilities

tags:
  - redirect
  - open-redirect
  - phishing

requests:
  - method: GET
    path:
      - "/redirect?url={{payload}}"
      - "/goto?url={{payload}}"
      - "/redir?target={{payload}}"
      - "/jump?url={{payload}}"
    
    attack: batteringram
    payloads:
      payload:
        - "https://evil.com"
        - "//evil.com"
        - "https:evil.com"
        - "/\\evil.com"
        - "https://google.com"
    
    redirects: false                 # Don't follow redirects
    
    matchers:
      - type: status
        status:
          - 301
          - 302
          - 303
          - 307
          - 308
      
      - type: word
        part: header
        words:
          - "Location: https://evil.com"
          - "Location: //evil.com"
          - "Location: https://google.com"
        condition: or
```

### Example 8: Path Traversal

```yaml
id: path-traversal
name: Path Traversal / LFI
author: Phantom Team
severity: high
description: Detects path traversal vulnerabilities

tags:
  - lfi
  - traversal
  - file-inclusion

requests:
  - method: GET
    path:
      - "/download?file={{payload}}"
      - "/read?path={{payload}}"
      - "/include?page={{payload}}"
    
    attack: batteringram
    payloads:
      payload:
        - "../../../../etc/passwd"
        - "..\\..\\..\\..\\windows\\win.ini"
        - "/etc/passwd"
        - "C:\\windows\\win.ini"
        - "....//....//....//etc/passwd"
    
    matchers:
      - type: regex
        regex:
          - "root:.*:0:0:"            # Linux /etc/passwd
          - "\\[extensions\\]"        # Windows win.ini
        condition: or
    
    extractors:
      - type: regex
        name: passwd_content
        regex:
          - "(root:.*:0:0:[^:]*:[^:]*:[^\n]+)"
        group: 1
```

---

## ✅ Best Practices

### 1. Template Naming

**Good:**
```yaml
id: cve-2024-1234-rce
name: CVE-2024-1234 - Remote Code Execution in Product X
```

**Bad:**
```yaml
id: template1
name: Test
```

### 2. Use Descriptive Matchers

**Good:**
```yaml
matchers:
  - type: word
    words:
      - "SQL syntax error"
      - "mysql_fetch_array()"
    name: sql_error_indicators
```

**Bad:**
```yaml
matchers:
  - type: word
    words:
      - "error"
```

### 3. Add Context

**Always include:**
- `author` - Who created this
- `description` - What it detects
- `severity` - How critical
- `tags` - Categories
- `references` - External links

### 4. Test Your Templates

```python
# Test on known vulnerable site first
scanner = SignatureScanner()
result = await scanner.scan_with_yaml(
    template, 
    "http://testphp.vulnweb.com"  # Known vulnerable
)

assert result['matched'] == True
```

### 5. Handle False Positives

**Use negative matchers:**
```yaml
matchers:
  # Match error
  - type: word
    words:
      - "SQL error"
  
  # But NOT if it's Adminer (SQL tool)
  - type: word
    words:
      - "Adminer"
    negative: true
```

### 6. Optimize Performance

**Test most likely paths first:**
```yaml
path:
  - "/admin"                        # Most common
  - "/administrator"
  - "/admincp"                      # Less common
```

**Use `stop-at-first-match`:**
```yaml
stop-at-first-match: true          # Don't waste time after finding it
```

### 7. Use Variables for Reusability

**Instead of:**
```yaml
body: '{"user":"admin","pass":"password"}'
```

**Use:**
```yaml
variables:
  username: admin
  password: password

body: '{"user":"{{username}}","pass":"{{password}}"}'
```

### 8. Document Complex Logic

```yaml
# This template detects SQL injection by:
# 1. Sending payloads with single quotes
# 2. Checking for database error messages
# 3. Extracting the specific error for analysis
```

---

## 🐛 Troubleshooting

### Template Not Matching

**Check:**
1. **URL is correct**: `https://example.com` (include protocol)
2. **Path is correct**: `/admin` not `admin`
3. **Matchers are appropriate**: Use regex for complex patterns
4. **Check response manually**: What does the server actually return?

**Debug:**
```python
result = await scanner.scan_with_yaml(template, url)
print(result)  # Check what's returned
```

### Validation Errors

**Error: "Missing required field: id"**
```yaml
# Add this
id: my-template-id
```

**Error: "Invalid severity"**
```yaml
# Must be one of: info, low, medium, high, critical
severity: critical  # Not "crit" or "very-high"
```

**Error: "At least one request is required"**
```yaml
# Add requests section
requests:
  - method: GET
    path:
      - "/"
```

### Matchers Not Working

**Word matcher not matching:**
```yaml
# Check case
matchers:
  - type: word
    words:
      - "Error"                      # Won't match "error"
    case-insensitive: true           # Add this
```

**Regex not matching:**
```yaml
# Escape special characters
matchers:
  - type: regex
    regex:
      - '\[error\]'                  # Not "[error]" (brackets are special)
```

### Extractors Returning Nothing

**Check:**
1. **Pattern is correct**: Test regex on regex101.com
2. **Part is correct**: `part: body` or `part: header`
3. **Group number**: `group: 1` (not `group: 0` unless you want entire match)

**Debug:**
```yaml
extractors:
  - type: regex
    name: debug
    regex:
      - '.*'                         # Match everything
    group: 0                         # Full match
```

### Variables Not Replacing

**Wrong:**
```yaml
path:
  - "/api?user={username}"           # Won't work
```

**Correct:**
```yaml
path:
  - "/api?user={{username}}"         # Use double braces
```

---

## 📖 Quick Reference Card

### Template Structure
```yaml
id: required-unique-id
name: Required Name
severity: info|low|medium|high|critical
requests:
  - method: GET|POST|PUT|DELETE
    path: ["/path"]
    matchers: [...]
```

### Matcher Types
- `word` - Exact string matching
- `regex` - Regular expressions
- `status` - HTTP status codes
- `size` - Content length
- `binary` - Binary patterns (hex)
- `dsl` - DSL expressions

### Extractor Types
- `regex` - Extract with regex
- `kval` - Extract headers
- `json` - Extract from JSON
- `xpath` - Extract from HTML/XML
- `dsl` - Extract with DSL

### DSL Functions
- Encoding: `base64()`, `url_encode()`, `hex_encode()`
- Hashing: `md5()`, `sha1()`, `sha256()`
- String: `to_lower()`, `to_upper()`, `trim()`, `len()`
- Random: `rand_int()`, `rand_text_alphanumeric()`

### Context Variables
- `{{BaseURL}}` - Full URL
- `{{Hostname}}` - Domain
- `{{Port}}` - Port number
- `{{Path}}` - URL path
- `{{Scheme}}` - http/https

---

## 🎓 Next Steps

1. **Start Simple**: Copy the "Hello World" example and modify it
2. **Test on Known Vulnerable Sites**: 
   - http://testphp.vulnweb.com
   - http://demo.testfire.net
3. **Study Existing Templates**: Look at Nuclei templates for inspiration
4. **Build Your Library**: Create templates for your common findings
5. **Share**: Contribute to the Phantom community

---

*"Ni Dieu ni maître ❤️"*

**Phantom Framework © 2026**  
