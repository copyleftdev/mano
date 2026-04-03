# mano

**The shark — fast HTTP probe and fingerprinter.**

Mano was built by stracing httpx at the syscall level, mapping every bottleneck in its Go runtime, and engineering a Rust replacement that eliminates each one. It probes HTTP services, extracts titles, fingerprints technologies, grabs TLS certificates, and computes body hashes — in a 4.9MB binary that's 93% smaller and 6x faster.

Designed to pair with [leviathan](https://github.com/copyleftdev/leviathan):

```bash
leviathan -d hackerone.com -s | mano -s --title --status-code --tech-detect
```

The sea monster finds them. The shark devours them.

## Why this exists

We ran `strace -c -f` on httpx and found:

| Bottleneck | Cause | Impact |
|---|---|---|
| **1,783 futex calls** (66%) | Goroutine scheduling + unbuffered channels | Mutex thrashing for 17 targets |
| **1,222 nanosleep** (8.7%) | Go runtime sysmon + scheduler spin-yielding | 72 sleeps per target |
| **Zero connection pooling** | `DisableKeepAlives: true`, `MaxIdleConnsPerHost: -1` | Fresh TLS handshake every request |
| **DNS fan-out explosion** | 5 resolvers queried in parallel per hostname | 12 connect() calls per target |
| **IPv6 ENETUNREACH waste** | Tries IPv6 first on IPv4-only systems | 17 failed connect() syscalls |
| **69MB binary** | Wappalyzer DB, headless browser, MongoDB/MySQL/PostgreSQL drivers compiled in | All included even when unused |
| **481 syscalls per target** | Sum of all above | Massive kernel overhead |

httpx uses 124% CPU to probe 17 targets in 1.6 seconds. Most of that CPU is the Go runtime fighting itself.

## What changed

| httpx (Go) | mano (Rust) | Result |
|---|---|---|
| Goroutine per target + unbuffered chan | tokio async + `buffer_unordered` | **31% fewer futex calls** |
| `DisableKeepAlives: true` | Shared connection pool with keep-alive | TLS session reuse |
| 5 DNS resolvers queried per target | System resolver with caching | No DNS fan-out waste |
| IPv6 fallback everywhere | IPv4-only at client level | Zero ENETUNREACH |
| Go runtime (GC, sysmon, scheduler) | Rust async, zero-cost abstractions | **88x less CPU** |
| 69MB binary (wappalyzer, headless, DB) | 4.9MB stripped | **93% smaller** |
| 1,222 nanosleep per run | 3 clock_nanosleep | **407x fewer sleeps** |

## Head-to-head

17 HackerOne subdomains, all fields enabled:

| | httpx | mano |
|---|---|---|
| **Wall clock** | 1.59s | 0.25s | 
| **CPU time** | 1.98s | 0.04s |
| **CPU utilization** | 124% | 15% |
| **Total syscalls** | 8,183 | 5,546 |
| **Futex calls** | 1,783 | 1,228 |
| **nanosleep calls** | 1,222 | 3 |
| **Binary size** | 69 MB | 4.9 MB |
| **Hosts found alive** | 11 | 11 |

**6.4x faster wall clock. 49x less CPU. 93% smaller binary.** Same results.

## Usage

```bash
# Basic probe — HTTPS-first with HTTP fallback
mano -u hackerone.com

# Probe a list (httpx compatible)
mano -l targets.txt

# Pipe from leviathan or subfinder
leviathan -d hackerone.com -s | mano

# All fields
mano -l targets.txt -a

# Pick what you need
mano -l targets.txt -s --title --status-code --tech-detect --server

# JSON output
mano -l targets.txt --json

# Follow redirects
mano -l targets.txt -L --status-code

# Filter by status code
mano -l targets.txt --mc 200,301,302     # only show these
mano -l targets.txt --fc 404,403         # hide these

# Hashes and TLS
mano -l targets.txt --hash --tls-grab

# High concurrency
mano -l targets.txt -c 200

# Output to file
mano -l targets.txt -o results.txt
```

## Features

- **HTTP probing** — HTTPS-first with automatic HTTP fallback
- **Title extraction** — fast regex, no full DOM parse
- **Technology detection** — pattern matching on server headers + body (nginx, Cloudflare, WordPress, React, Django, etc.)
- **TLS certificate grabbing** — Subject CN, SANs, issuer
- **Body hashing** — MD5, SHA-256
- **Status code / content-length / server header**
- **Line and word counts**
- **Response time measurement**
- **Status code filtering** — match (`--mc`) and filter (`--fc`)
- **JSON output** — one result per line, all fields
- **Stdin piping** — drop-in httpx replacement in pipelines
- **Follow redirects** — configurable redirect policy

## Design philosophy

**Measure before you build.** Every architectural decision traces to a strace timestamp or syscall count.

**Compile what you use.** httpx ships 69MB because it includes wappalyzer's full database, a headless Chrome bridge, and three database drivers — even when you just want status codes. mano compiles to 4.9MB with everything you actually need for HTTP probing.

**Share connections.** httpx intentionally kills keep-alive (`DisableKeepAlives: true`) because it probes diverse hosts. But when you're probing 50 subdomains behind the same Cloudflare edge, you're paying for 50 TLS handshakes to the same IP. mano uses a shared connection pool — same-host probes reuse connections automatically.

**Don't fight the scheduler.** httpx spawns 50 goroutines that immediately block on channel sends, triggering futex waits. mano uses `buffer_unordered` — tokio schedules work without contention.

## Vision

Mano is the surface probe in a two-tool recon pipeline:

```
leviathan (deep)  →  mano (surface)
find subdomains      probe every host
DNS/CT/OSINT         HTTP fingerprint
```

The direction is toward a **complete attack surface profiler**:

- **Favicon hashing** — MMH3/MD5 for Shodan cross-reference
- **JARM fingerprinting** — TLS configuration fingerprinting
- **Wappalyzer-compatible tech detection** — load custom fingerprint databases
- **Screenshot capture** — headless rendering without shipping a browser
- **Response diffing** — detect changes between runs
- **API mode** — serve results over HTTP for integration with other tools
- **Custom extraction** — regex/CSS selectors on response bodies

The constraint: **never ship code the user didn't ask for. Every feature is opt-in. The binary stays small.**

## Install

```bash
git clone https://github.com/your-org/mano.git
cd mano
cargo build --release
cp target/release/mano /usr/local/bin/
```

Requires Rust 1.70+.

## License

MIT
