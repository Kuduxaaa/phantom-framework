from app.core.scanners.signature_scanner import SignatureScanner

# Initialize scanner
scanner = SignatureScanner()

# Define a simple detection template
template = """
id: admin-panel-check
name: Admin Panel Detection
severity: low

requests:
  - method: GET
    path:
      - "/admin"
      - "/administrator"
    
    matchers:
      - type: status
        status:
          - 200
      
      - type: word
        words:
          - "admin"
          - "dashboard"
"""

# Scan target
result = await scanner.scan_with_yaml(template, "https://example.com")

if result['matched']:
    print(f"Found: {result['signature_name']}")
    print(f"Severity: {result['severity']}")