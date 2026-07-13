# Web Guard — Real-time malicious-JavaScript attack research

Research backing the **Web Guard** tab. Goal: catch attacks that deliver or run
malicious JavaScript in the browser *in real time*, and map each class to a
signal a native Windows agent can actually observe (no browser plugin required).

A native app cannot see inside the browser's JS engine without an extension or a
debugger attach. What it *can* observe honestly:

1. **Network** — every browser process' outbound TCP connections (`GetExtendedTcpTable`).
   Resolve a curated blocklist of malicious-JS infrastructure and flag any browser
   connection that lands on it. This is the primary real-time signal.
2. **Disk** — loose JavaScript that the browser fetched and persisted: **installed
   extension scripts** (`...\User Data\*\Extensions\<id>\<ver>\*.js`). Scan them for
   obfuscation markers. (HTTP cache is a binary blob format, so loose `.js` there is
   not reliably scannable — extensions are the real loose-JS surface.)
3. **Process** — script hosts spawned by a browser (`mshta`, `wscript`, `powershell`)
   are a strong drive-by-download tell (covered by the existing Sys Watch / ETW pages).

## Attack taxonomy → detectable signal

| Attack | What the JS does | Real-time signal Web Guard uses |
|---|---|---|
| **Cryptojacking** | In-page miner (CoinHive-style / WASM) pegs CPU, opens a WebSocket to a mining pool | Browser → known miner-JS / stratum-over-WS pool domain (network). Still the most reliably *live*-matching class. |
| **Magecart / formjacking (skimmers)** | Injected checkout-page JS exfiltrates card + form fields to an attacker "gate" | Browser → known skimmer gate domain (network); gates often masquerade as `*-analytics`/`*-cdn` lookalikes |
| **Malvertising** | Ad-network JS silently redirects to an exploit/scam chain | Browser → known malvertising redirector/gate (network) |
| **Exploit kits (drive-by)** | Landing-page JS fingerprints the browser, serves an exploit, drops a payload | Browser → known EK gate (network) **and** browser spawning a script host (process) |
| **Obfuscated / packed JS** | `eval`/`atob`/`fromCharCode`/`\xNN` unpacking to hide intent | Static scan of extension JS for obfuscation markers (disk) |
| **Malicious / hijacked extension** | Extension injects tracking or skimming JS into every page | Same extension-JS scan; miner/skimmer keywords + heavy obfuscation |
| **Tracker / stalkerware C2** | JS beacons device + behavior to an analytics/C2 endpoint | Browser → known tracker/C2 host (network) |
| **Tech-support-scam / browser locker** | Fullscreen JS loop + fake AV audio traps the user | Browser → known scam/locker host (network) |

Out of scope for a plugin-less agent (documented so we don't overclaim):
stored/reflected/DOM **XSS**, **clickjacking**, **prototype pollution**,
**service-worker** abuse, **tabnabbing** — these live entirely inside a single
page's DOM and need an in-browser hook to observe. Web Guard states this plainly
rather than pretending to intercept every `eval()`.

## Detection model (as implemented)

- **Blocklist** — categorized IOC domains (miners, skimmer gates, malvertising,
  EK gates, tracker/C2, scam/locker), resolved to IPs on a background thread.
- **Live monitor** — every 3 s, aggregate browser-owned TCP connections whose
  remote IP is in the resolved set; show Time / Process / Endpoint / Category /
  Status / Count. Only **browser** processes count (chrome, msedge, firefox,
  brave, opera, vivaldi, chromium).
- **Extension scan** — best-effort walk of Chromium-family extension dirs; a `.js`
  file is *flagged* when it hits ≥2 obfuscation markers or a miner keyword.
- **Control** — per-category enable + a master BLOCKING/OPEN mode. **Apply** shells
  out elevated to `Harden-WebGuard.ps1`, which null-routes the IOC hosts (hosts
  file, reversible markers) and adds an outbound firewall block rule. **Revert**
  removes both.

The IOC list is representative and extensible — miner/pool domains match live
today; historical EK/skimmer gates are kept as IOCs. This is a heuristic
network+disk monitor, not a browser sandbox.
