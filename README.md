# td-agent: a novel Rust Linux RAT that hides in plain TLS

*Defensive threat-intelligence writeup. First public documentation of the "td-agent" / "TD" implant
framework (`0day-lib` campaign). Description and detection only — no decryptor or exploit code.*

---

## TL;DR

**td-agent** is a previously-undocumented, bespoke **Rust** Linux remote-access implant, caught in the wild
by a honeypot sensor on 2026-11-15. It is notable for three reasons:

1. **It hides in plain TLS.** Unlike most custom RATs that roll their own crypto (and are therefore
   fingerprintable and sinkholeable), td-agent runs its control channel as a thin application-layer protocol
   (`td-enc-v1`) over **standard TLS 1.3** (`rustls`). There is no bespoke transport cipher to break — and no
   custom-crypto handshake to signature.
2. **It's a full access/pivot platform, not a bot.** Remote shell, file transfer, on-host HTTP server, port
   listeners, and tunnelling over four transports — not a DDoS/miner payload.
3. **Its anti-analysis is evasion-by-stalling.** On detecting an analysis environment it does not exit or
   crash (the usual tell); it keeps beaconing but silently withholds its operational stage, so a sandbox sees
   a live-but-inert process.

It was near-undetected at capture time, delivered by a short, disposable two-tier campaign off throwaway
infrastructure that has since been torn down. Builder artifacts in the binary indicate td-agent is one
instance of a **reusable kit**, so the host- and network-level fingerprints below are expected to recur in
future campaigns.

---

## How it was found

A web-RCE spraying host hit two honeypot sensors on **2026-11-15** over a ~3.5-hour window (07:33–10:58 UTC),
firing directory-traversal and shell-injection probes across a spread of HTTP ports. One chain completed: a
small shell stager was fetched, which pulled the td-agent implant from a domain-fronted CDN. The implant is
the subject of this writeup.

---

## Delivery chain — the `0day-lib` campaign

A deliberately disposable, **two-tier** delivery architecture:

```
  web-RCE sprayer (202.160.70.69, Taiwan)
        │  traversal + shell injection
        ▼
  stager  http://188.165.53.219:8080/stager_lib.sh   (raw IP, OVH FR, plain HTTP)
        │  selects arch, fetches binary
        ▼
  implant https://cdn.876553.xyz/<path-secret>/dl/<uuid>?a=<arch>   (domain, HTTPS, tokenised)
        │
        ▼
  td-agent  (1.5 MB static-PIE Rust ELF, run as `<binary> --bypass`)
```

The stager (`stager_lib.sh`) self-identifies the campaign in a comment — *"library 0day campaign stager -
CDN binary only (no R2 fallback)"* — sets `TD_PROJ=0day-lib`, installs a **3-minute cron respawn**, spoofs a
`Wget/1.21.4` User-Agent, and selects one of five architectures (`arm64`/`armv7`/`armv6`/`x86`/`x64`) via the
`?a=` query parameter. The *"no R2 fallback"* note indicates the kit's normal delivery model is a CDN plus a
**Cloudflare R2** object-storage fallback — i.e. the `.xyz` "CDN" is cloud-fronted storage, not an
operator-owned server. The only operator-rented box in the chain is the OVH stager VPS.

**Infrastructure is dead** (verified 2026-11-23): `876553.xyz` returns **NXDOMAIN** at the registry
(de-registered), and the OVH stager IP answers RSTs on all web ports (service torn down). This was a
time-boxed campaign run off burnable infrastructure — which is exactly why the durable fingerprints matter
more than the (now-dead) IOCs.

---

## The implant

- **Language/build:** Rust, static-PIE ELF, multi-architecture. Transport crypto crate fingerprint:
  **`rustls-0.23.44`** with the **`oxitls-rustcrypto-provider`** backend.
- **Launch:** requires the **`--bypass`** flag to enter bot mode; without it the process exits immediately.
  A **`--nosb`** flag (and `TD_NOSB` env) disables the sandbox screen.
- **Configuration** is supplied via environment (the kit substitutes a build-time `@@TDHOST@@` placeholder):
  `TD_HOST`, `TD_PORT`, `TD_WSPATH`, `TD_WSPORT`, `TD_WSGATE`, `TD_CDN`, `TD_TUNPORT`, `TD_TUNPROTO`,
  `TD_VIA`, `TD_PROJ`, `TD_LOCK`, `TD_IDSALT`, `TD_NOSB`.
- **On-host artifacts:** a run lock `/tmp/.td-agent.lock`, and `/tmp/.dsync_rs.cache` holding a generated
  **bot UUID** (stable identity across restarts; related to `TD_IDSALT`). A debug log `ag_dbg.log` and a
  `.td-www` working directory also appear in the binary.

### `td-enc-v1` — control protocol

- **Transport = standard TLS 1.3** (RFC 8446) via `rustls` + `oxitls-rustcrypto-provider`. All record
  encryption, key schedule, and X25519 key agreement are the stock TLS stack. **There is no bespoke
  application-layer cipher or KDF** — the app protocol rides the TLS session keys.
- **Handshake:** `ENCSTART` (client) → `ENCOK` (server), versioned on the wire as `ENCSTART1` / `ENCOK1`
  (the `1` = protocol version `td-enc-v1`). `ENCSTART` carries a magic, a `u32` big-endian version, and a
  32-byte random nonce (replay/session binding — not a keying input).
- **Framing:** 4-byte big-endian length prefix + payload; error states `bad frame len` / `bad enc chunk` /
  `enc auth fail` / `no complete frame yet`.
- **Opcodes are ASCII keyword tokens** (not opaque bytes): `HELLO`/`OK`, `EXEC`, `RESULT`, the shell family
  `SHSTART`/`SHSIZE`/`SHDATA`/`SHEND`/`SHCLOSED`, `UDP`, the tunnel family `TUN`/`TUNOK`/`TUNPING`/`TUNPLAIN`,
  `RECONN`, `BYE`.
- **Transports:** four are selectable via `TD_TUNPROTO` — `tls`, `ws`, `tcp`, `udp`. In the WebSocket mode
  the endpoints are `/<path-secret>/wsGate` and `/<path-secret>/wsTunnel`, gated by a **gate token**
  presented on the upgrade. A **plaintext tunnel mode** (`TUNPLAIN` / `TD_TUNPLAIN`) also exists — in that
  mode the ASCII protocol tokens travel the wire **in cleartext**.
- **Correlation IOC:** the URL **path-secret is reused** across the delivery CDN
  (`cdn.876553.xyz/<secret>/dl/…`) and the C2 WebSocket endpoints (`/<secret>/wsGate`, `/<secret>/wsTunnel`).
  One per-deployment secret links delivery infrastructure to C2 infrastructure.

### Capabilities

td-agent is a general-purpose access/pivot platform. Its command surface (ASCII tokens routed by an
ordered dispatcher) includes:

| Command | Function |
| :--- | :--- |
| `EXEC` | Execute a command |
| `SHSTART`/`SHSIZE`/`SHDATA`/`SHEND`/`SHCLOSED` | Interactive PTY shell (`/bin/sh -i`, winsize) |
| `UPLOAD` / `DELETE` / `LIST` | File write / delete / directory listing |
| `LISTEN` | Open a listener on the victim |
| `HTTPD` / `UNHTTPD` | Start / stop an HTTP server on the victim |
| `TUN` / `UDP` | TCP / UDP tunnelling and relay |
| `RESULT` / `RECONN` / `BYE` | Result return / reconnect / teardown |

### Anti-analysis — a stall-gate, not a kill-switch

At startup the implant builds a list of indicator substrings — **`sandbox`, `malware`, `cuckoo`, `virus`,
`sample`, `analys`** — and screens an environment buffer against them. Observed behaviour (lab detonation)
and static control-flow (decompile) agree:

- The **C2 beacon is not gated** — the implant connects to its C2 regardless of these indicators.
- When an indicator **matches**, the implant does **not** exit. It increments a counter, delays, and
  **loops** — withholding progression to its operational stage. When nothing matches, it proceeds normally.
- The screen is **not** keyed on hostname/username/binary path (poisoning those in a lab A/B had no effect);
  adjacent code reads `/sys/fs/cgroup`, indicating the detection is **container/cgroup-based**.

The design intent is to present as **alive-but-inert** under analysis — avoiding the obvious tell of
exiting-on-detection while still wasting analyst time. **Note:** td-agent has *no* ptrace/debugger
anti-analysis — it runs fully under a tracer.

Heavier persistence (init-system hooks, etc.) is **post-registration**: it is not installed until the
implant completes a live C2 handshake, so a sandbox with no real C2 observes only the lock file and the
cached bot UUID.

---

## Provenance & attribution

Behavioural, not vendor attribution. Two concrete indicators:

- **The operator's working language is Chinese** — operator-facing strings in the binary are Chinese
  (e.g. HTTP-hosting status/error messages).
- **td-agent is a kit.** The binary carries a build-time template placeholder **`@@TDHOST@@`** and ships a
  default gate token **`ChangeMe_GateToken_9f3K`** (an unchanged placeholder). Combined with the `TD_PROJ`
  campaign field, this is a builder/framework, not a one-off tool — expect the same fingerprints under other
  campaign names and infrastructure.

---

## Detection

Because td-agent rides stock TLS, payload-inspection signatures only fire against its **plaintext** tunnel
mode and against the **static binary**. The most durable detection is host- and binary-based.

### YARA (static binary)

```yara
rule td_agent_rust_rat
{
    meta:
        description = "td-agent / TD framework Rust Linux RAT (td-enc-v1)"
        reference   = "defensive threat-intel, 0day-lib campaign"
    strings:
        $p1 = "td-enc-v1" ascii
        $p2 = "ENCSTART1" ascii
        $p3 = "ENCOK1" ascii
        $g  = "ChangeMe_GateToken" ascii        // kit default; match prefix
        $t1 = "TD_TUNPROTO" ascii
        $t2 = "TD_WSGATE" ascii
        $t3 = "TD_IDSALT" ascii
        $tpl = "@@TDHOST@@" ascii                // builder template placeholder
        $a1 = ".td-agent.lock" ascii
        $a2 = ".dsync_rs.cache" ascii
    condition:
        uint32(0) == 0x464c457f and             // ELF
        (
            ( $p1 and 2 of ($p2,$p3,$g,$tpl) ) or
            ( 4 of ($t1,$t2,$t3,$a1,$a2) )
        )
}
```

### Suricata (plaintext-tunnel variant / cleartext deployments)

```
alert tcp any any -> any any (msg:"td-agent td-enc-v1 handshake (ENCSTART)"; \
    flow:established,to_server; content:"ENCSTART"; depth:16; \
    classtype:trojan-activity; sid:4200001; rev:1;)

alert tcp any any -> any any (msg:"td-agent td-enc-v1 handshake ack (ENCOK)"; \
    flow:established,to_client; content:"ENCOK"; depth:16; \
    classtype:trojan-activity; sid:4200002; rev:1;)

alert http any any -> any any (msg:"td-agent wsGate upgrade with default gate token"; \
    flow:established,to_server; content:"ChangeMe_GateToken"; http.header; \
    content:"wsGate"; http.uri; classtype:trojan-activity; sid:4200003; rev:1;)
```

### Host / behavioural

- Files: `/tmp/.td-agent.lock`, `/tmp/.dsync_rs.cache` (36-byte UUID).
- A process invoked with a lone **`--bypass`** argument.
- Unexpected on-host HTTP listener or outbound tunnels from a server process.
- TLS client fingerprint (JA3/JA4) consistent with `rustls-0.23.44` from a non-browser Linux process.
- **The beacon is not suppressed in a sandbox** — network monitoring catches td-agent even where its
  stall-gate hides its on-host behaviour. To observe full behaviour in a lab, detonate somewhere that does
  **not** look containerised (the evasion is cgroup/container-keyed) and provide a live or emulated C2.

---

## Indicators of compromise

| Type | Value |
| :--- | :--- |
| Implant SHA-256 | `babd64048ff87611dfa55af74a882d62e4d6eb42e51fc0de495b74226bc90845` |
| Stager SHA-256 | `49fad589b95e8ed3f9c2816691ceb2906a4fb91ebbd51584ce5ecc124f4c9abc` |
| Sprayer IP | `202.160.70.69` (SparkTech LTD, AS215595, TW) |
| Stager host | `188.165.53.219:8080` (OVH SAS, AS16276, FR) — `/stager_lib.sh` |
| Delivery CDN | `cdn.876553.xyz` (now NXDOMAIN) |
| Delivery URL | `https://cdn.876553.xyz/Q1fc8a9OCb7AsC6f/dl/7e86f0a7-1f6f-4568-ace9-5569b17bb75d?a=<arch>` |
| Path-secret (CDN + C2 WS) | `Q1fc8a9OCb7AsC6f` |
| C2 WS endpoints | `/Q1fc8a9OCb7AsC6f/wsGate`, `/Q1fc8a9OCb7AsC6f/wsTunnel` |
| Gate token (kit default) | `ChangeMe_GateToken_9f3K` |
| Campaign ID | `TD_PROJ=0day-lib` |
| Host artifacts | `/tmp/.td-agent.lock`, `/tmp/.dsync_rs.cache` |
| Protocol markers | `td-enc-v1`, `ENCSTART1`, `ENCOK1` |

---

## Status

The observed campaign's infrastructure is dead (domain de-registered, stager torn down). td-agent itself is
a reusable kit; the host-, binary-, and protocol-level fingerprints above are the durable intelligence and
are expected to recur under new campaign names and fresh infrastructure.

*SHA-256 samples can be submitted to MalwareBazaar for tracking. This document contains no decryptor,
exploit, or offensive tooling.*
