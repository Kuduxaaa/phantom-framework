# ph-proxy — Phantom Intercepting Proxy

## What is ph-proxy?

ph-proxy is a forward intercepting proxy built into Phantom Framework. It sits between the tester and the target, capturing HTTP and HTTPS traffic for analysis, replay, and fuzzing as part of the security testing workflow.

HTTPS traffic is decrypted via MITM (Man-in-the-Middle) TLS interception — the proxy generates per-domain certificates on the fly, signed by its own CA. This gives full visibility into encrypted request/response data.

## Purpose

ph-proxy serves as the traffic interception layer in Phantom's bug bounty and penetration testing pipeline:

- **MITM TLS interception** — Decrypt HTTPS traffic using on-the-fly certificate generation signed by a local CA
- **Request capturing** — Log all HTTP/HTTPS requests and responses passing through the proxy
- **HTTPS CONNECT handling** — Intercept CONNECT tunnels, perform TLS handshake with the client, and proxy decrypted traffic
- **WebSocket proxying** — Bidirectional WebSocket tunnel with full message forwarding (TEXT, BINARY, PING/PONG)
- **Chunked streaming** — 64KB buffered response streaming with backpressure handling
- **Verbose mode** — Full request/response header logging with `-v` flag

## Architecture

```
Browser / CLI Scanner
        |
        |  (configure proxy: localhost:8080)
        v
  +-------------+
  |  ph-proxy   |
  |  :8080      |
  |             |
  |  HTTP    ---+--> forward request, log, stream response
  |             |
  |  CONNECT ---+--> TLS handshake (fake cert signed by CA)
  |             +--> decrypt traffic
  |             +--> forward to upstream over real TLS
  |             +--> log decrypted request/response
  |             |
  |  WS      ---+--> bidirectional WebSocket tunnel
  +-------------+
        |
        v
   Target Server
```

### Components

| Module | Location | Purpose |
|--------|----------|---------|
| **ProxyHandler** | `core/proxy/handler.py` | Request entry point — HTTP, CONNECT/MITM, WebSocket branching |
| **CertManager** | `core/proxy/certs.py` | CA generation, per-domain cert creation, SSL context caching |
| **ProxySettings** | `core/proxy/config.py` | Port and timeout configuration |
| **Headers** | `core/proxy/headers.py` | Hop-by-hop header stripping |
| **Streamer** | `core/proxy/transport/streamer.py` | 64KB chunked response streaming |
| **WebSocket** | `core/proxy/transport/websocket.py` | Bidirectional WebSocket tunnel |
| **Server** | `core/proxy/server.py` | Raw aiohttp server factory and listener |

## Setup

### 1. Install dependencies

```bash
make install
```

This installs `aiohttp`, `cryptography`, and other required packages.

### 2. Start the proxy

```bash
ph proxy          # default port 8080
ph proxy -p 9090  # custom port
ph proxy -v       # verbose: show full headers
make proxy        # via Makefile
```

### 3. Install the CA certificate

On first run, ph-proxy generates a root CA certificate at `~/.ph-proxy/ca.pem`. Install it in your browser to avoid certificate warnings:

**Firefox:** Settings > Privacy & Security > Certificates > View Certificates > Authorities > Import > select `~/.ph-proxy/ca.pem` > check "Trust this CA to identify websites"

**Chrome / Edge:** Settings > Privacy and security > Security > Manage certificates > Trusted Root Certification Authorities > Import > select `~/.ph-proxy/ca.pem`

**System-wide (Windows):** `certutil -addstore Root %USERPROFILE%\.ph-proxy\ca.pem`

### 4. Configure your browser

Set HTTP proxy to `127.0.0.1:8080`. All traffic (HTTP and HTTPS) will pass through ph-proxy.

## Usage

### With Phantom Scanner

Route scan traffic through ph-proxy to inspect what the scanner sends:

```bash
# Terminal 1: start the proxy with verbose logging
ph proxy -v

# Terminal 2: scan through the proxy
ph https://target.com --proxy http://127.0.0.1:8080
```

### CLI Output

**Normal mode** (`ph proxy`):
```
GET http://example.com/ -> 200
CONNECT google.com:443 -> MITM tunnel established
GET /search?q=test (via google.com) -> HTTP/1.1 200 OK
```

**Verbose mode** (`ph proxy -v`):
```
GET /search?q=test (via google.com) -> HTTP/1.1 200 OK
  >> GET /search?q=test HTTP/1.1
  >> Host: google.com
  >> User-Agent: Mozilla/5.0 ...
  >> Cookie: NID=...
  >>
  << HTTP/1.1 200 OK
  << Content-Type: text/html; charset=UTF-8
  << Set-Cookie: ...
  <<
```

## How MITM Works

1. Browser sends `CONNECT google.com:443 HTTP/1.1`
2. ph-proxy connects to the real `google.com:443` over TLS
3. ph-proxy sends `200 Connection Established` to the browser
4. ph-proxy performs a TLS handshake with the browser as server, using a certificate for `google.com` signed by the PhProxy CA
5. Browser sends decrypted HTTP request through the TLS tunnel
6. ph-proxy reads the plaintext request, logs it, forwards it to the real upstream
7. Upstream responds, ph-proxy logs the response, sends it back to the browser

The browser trusts the fake certificate because the PhProxy CA is installed in its trust store.

## Roadmap

### Request Interception

- **Intercept mode** — Pause requests/responses before forwarding, allowing manual inspection
- **Break rules** — Trigger interception based on URL patterns, methods, or headers
- **Scope filtering** — Only intercept in-scope traffic based on Vault scope rules

### Request Editor

- **Header editor** — Add, remove, or modify request headers before forwarding
- **Body editor** — Edit request body (JSON, form-data, raw)
- **Encoding tools** — Built-in base64, URL encoding, and hex converters

### Repeater

- **Request replay** — Resend any captured request with modifications
- **Tabbed interface** — Manage multiple repeater sessions in parallel
- **Response diff** — Compare responses across replayed requests

### Intruder

- **Attack modes** — Integration with Phantom's template engine (batteringram, pitchfork, clusterbomb)
- **Payload positions** — Mark injection points in captured requests
- **Result analysis** — Detect anomalies by response length, status code, and timing
- **Finding integration** — Save discovered vulnerabilities to Phantom's Finding model

### HTTP History

- **Full traffic logging** — Record all proxied requests/responses to the database
- **Search & filter** — Query by URL, status, method, content-type, or size
- **Export** — Export history in HAR and JSON formats

### Web Interface

- **Proxy dashboard** — Real-time traffic monitor in the Phantom Vue.js frontend
- **Visual request editor** — Point-and-click request modification
- **History browser** — Searchable, filterable traffic log with request/response viewer
