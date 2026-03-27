# ph-proxy — Phantom Intercepting Proxy

## What is ph-proxy?

ph-proxy is a forward intercepting proxy built into Phantom Framework. It sits between the tester and the target, capturing HTTP/HTTPS traffic for analysis, replay, and fuzzing as part of the security testing workflow.

## Purpose

ph-proxy serves as the traffic interception layer in Phantom's bug bounty and penetration testing pipeline:

- **Request capturing** — Log all HTTP/HTTPS traffic passing through the proxy
- **HTTPS tunneling** — CONNECT method support for transparent HTTPS proxying
- **WebSocket proxying** — Bidirectional WebSocket tunnel with full message forwarding (TEXT, BINARY, PING/PONG)
- **Chunked streaming** — 64KB buffered response streaming with backpressure handling

## Architecture

```
Browser / CLI Scanner
        │
        │  (configure proxy: localhost:8080)
        ▼
  ┌───────────┐
  │  ph-proxy │
  │  :8080    │
  │           │
  │  HTTP  ───┼──► forward request to target URL
  │  CONNECT ─┼──► TCP tunnel (HTTPS passthrough)
  │  WS    ───┼──► bidirectional WebSocket tunnel
  └───────────┘
        │
        ▼
   Target Server
```

### Components

| Module | Location | Purpose |
|--------|----------|---------|
| **ProxyHandler** | `core/proxy/handler.py` | Request entry point — HTTP, CONNECT, WebSocket branching |
| **ProxySettings** | `core/proxy/config.py` | Port and timeout configuration |
| **Headers** | `core/proxy/headers.py` | Hop-by-hop header stripping |
| **Streamer** | `core/proxy/transport/streamer.py` | 64KB chunked response streaming |
| **WebSocket** | `core/proxy/transport/websocket.py` | Bidirectional WebSocket tunnel |
| **Server** | `core/proxy/server.py` | aiohttp app factory and listener |

## Usage

### CLI

```bash
# Start proxy on default port (8080)
ph proxy

# Custom port
ph proxy -p 9090

# Debug logging
ph proxy -p 8080 -v

# Via Makefile
make proxy
```

### With Phantom Scanner

Route scan traffic through ph-proxy:

```bash
# Terminal 1: start the proxy
ph proxy

# Terminal 2: scan through the proxy
ph https://target.com --proxy http://127.0.0.1:8080
```

### With a Browser

Configure your browser's HTTP proxy to `127.0.0.1:8080`. All HTTP traffic will pass through ph-proxy. HTTPS connections use CONNECT tunneling.

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
