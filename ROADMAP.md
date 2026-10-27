# Seance Roadmap

Ordered by bang-for-time, biggest first. Checkboxes track what's landed on `main`.
Status snapshot from field testing (2026-07-07, work machine → Azure lab VM over static VPN):
core works — auth, input, paste-as-keystrokes all confirmed. Pain points: jitter on
big screen changes, no compressed encodings.

## Phase 0 — Quick wins (minutes each, permanent value)

- [x] **Remote → local clipboard**: `ServerCutText` already arrives; write it to the
  local clipboard instead of dropping it.
- [ ] **CI matrix build (Windows + macOS)**: workflow file is committed but has
  never been verified green — not a working pipeline yet. Builds and platform
  testing are local (Windows dev box + personal Mac) until this is proven.

## Phase 1 — Wire efficiency & perceived latency

The jitter, mechanistically: Raw encoding means a full 1080p refresh is ~8 MB over
the VPN. Three protocol features attack it:

- [x] **ZRLE encoding (16)**: zlib-compressed 64×64 tiles (palette / RLE / raw
  subencodings). 10–50× smaller for typical desktop content. The single biggest
  jitter fix.
- [x] **CopyRect encoding (1)**: window drags and scrolls become "copy this region"
  ops instead of retransmitted pixels.
- [x] **Cursor pseudo-encoding (-239)**: render the mouse cursor locally. Removes
  the cursor round-trip through the server — most of the *perceived* lag.

## Phase 2 — Binary transport

Base64-over-JSON-IPC was v0 scaffolding. Replace with:

- [x] Loopback WebSocket (bind 127.0.0.1, random port, one-time token in the URL);
  Rust ships decoded RGBA rects as binary frames: `[op][session_id][x][y][w][h][pixels]`.
  All draw ops (rect, copyrect, cursor, resize) ride this one channel — they are
  order-sensitive, so splitting transports would corrupt the canvas.
- [x] Frontend paints from `ArrayBuffer`, batched per `requestAnimationFrame`
  instead of per-rect.

WebSocket over Tauri binary IPC because the framebuffer is server-push;
request/response IPC is the wrong shape.

## Phase 3 — Tabs (multi-session)

- [x] Backend: `HashMap<u32, SessionHandle>` in `AppState`, with `active`
  (focused) and `pinned` (agent target) tab ids; all input commands take a
  `session_id`; the read loop tags every frame with its id.
- [x] Frontend: tab bar, one canvas per session, frames routed to the right
  canvas by id; `+`/close/switch.
- [x] Hidden tabs stop requesting incremental updates (per-session `active`
  flag; the read loop stops re-arming) so a backgrounded tab uses zero
  bandwidth; switching fires one full-frame request via `set_active`.
- [x] Agent Bridge scoping updated for tabs: the agent drives the **pinned**
  tab (or active if none pinned). Acting on a tab the operator isn't viewing is
  flagged `background` in the audit; autonomous-on-background requires an
  accepted warning that is itself logged.
- Needs live 2-tab verification (built + compiles + boots; the `session_id`
  camelCase→snake_case arg path is first-exercised here).

## Phase 4 — Connection manager

- [x] Saved hosts with credentials in the OS keychain (Windows Credential Manager /
  macOS Keychain) — turns the recent-hosts chips into a real connection manager,
  with user-named groups.

## Pillar: Agent Bridge (MCP) — the product-defining bet

This is what turns Seance from "a nice VNC viewer" into a new category: your
authenticated remote session becomes a supervised surface that any local AI
agent can see and drive. The agent never touches the host directly — it calls
tools on the Seance client (which holds the session), and the client is the only
thing that can relay a call to the host. **The human's live session is the
authorization boundary.**

Architecture:

```
AI agent (Claude Code / Desktop / Codex / any MCP client)
    │  MCP  (stdio or loopback HTTP, local-only, token-gated)
    ▼
Seance CLIENT  — exposes an MCP *server*; agents call its tools
    │  RFB connection to the active host
    ▼
Remote host
```

### Agentless bridge (any VNC server, zero host install)

Tools built entirely on primitives we already have. Works against TigerVNC,
RealVNC, macOS Screen Sharing, anything — because it's just a human's-eye view
plus input injection.

- [x] MCP server surface on the client — loopback HTTP, one-time bearer token
  (`src-tauri/src/agent/`). Hand-rolled minimal JSON-RPC (initialize /
  tools/list / tools/call). stdio transport shim still TODO for stdio-only agents.
- [x] `screenshot` — PNG of the server-side framebuffer (`rfb/framebuffer.rs`)
- [x] `type_text`, `key_combo` — reuse the input path (friendly key-name mapping)
- [x] `move_pointer`, `click`, `scroll` — reuse pointer events
- [x] `get_clipboard` / `set_clipboard` — remote clipboard read + ClientCutText
- [x] `list_tabs` / `switch_tab` — agent picks its target tab; the operator's
  view never moves
- [x] `list_saved_hosts` / `open_saved_host` — agent opens a saved host in a
  background tab with keychain credentials it never sees
- [x] Agent "sees" via pixels (vision/OCR on the caller's side); fuzzy but universal

### Security model — designed in, not bolted on

The line between "legitimate agent-driven remote admin" and "a RAT" is consent,
visibility, and audit. These are core, not settings. The standing principles and
feature-review checklist live in [SECURITY.md](SECURITY.md).

- [x] **Consent modes**: ask-every-call / allow-list of tools / autonomous. Default
      is ask; an "ask" call blocks on operator approval and times out denied (120s).
- [x] **Live visibility**: in-client activity panel (`AgentPanel.tsx`) shows every
      tool call — requested / completed / denied / error — as it happens.
- [x] **Audit log**: append-only `agent-audit.jsonl` in the app data dir
      (timestamp, agent id, tool, args, decision, result).
- [x] **Local-only transport**: MCP server binds 127.0.0.1 with a one-time bearer
      token; never exposed to the network.
- [x] **Session scoping**: screen/input tools reach only the pinned or active
      tab. The agent can open new sessions only to operator-saved hosts, gated
      by the consent policy like every other tool.

- [x] **Renderer secret exposure reduced**: saved host passwords are consumed
      backend-side for saved/reconnect flows; renderer clipboard permissions are
      removed; a strict CSP is enabled; the MCP token is no longer returned with
      bridge status.
- [x] **Native Agent Bridge token copy flow**: copy the MCP token and setup
      command directly from Rust so the token never enters renderer state.
- [x] **Allow-list editor**: let the operator choose the exact tools that
      auto-approve in allow-list mode, and preserve that list when switching
      consent modes.
- [x] **Tamper-evident audit log**: hash-chain audit entries so later edits or
      removed lines are detectable from the recorded tip.
- [x] **MCP local transport rate limiting**: authenticated MCP requests are capped
      to a local burst/window to limit runaway clients and accidental loops.
- [x] **Renderer command-surface narrowing**: renderer-originated input commands
      can only affect the active visible tab; background/pinned agent actions stay
      on the audited Agent Bridge path.
- [x] **Manual password state lifetime reduced**: manually entered passwords are
      cleared from React state as soon as a connect attempt is submitted.
- [x] **Security stance guideline**: root `SECURITY.md` defines the product's
      security principles, trust boundaries, and feature-review checklist.
- [ ] **Audit log retention policy**: define rotation, export, and at-rest
      protection expectations.
- [ ] **MCP local socket/pipe transport option**: consider Unix socket / named
      pipe transport where available.
- [ ] **Native manual-password entry flow**: consider moving manual credential
      entry into Rust/native UI so first-time passwords never enter renderer JS.

### Sequencing

The agentless bridge is buildable on today's primitives, but its value rides on
input/screenshot reliability — so it lands cleanest **after Phase 2 (binary
transport)**, when the pixel path is solid enough to hand an agent trustworthy
screenshots.

## Phase 5 — Later (real, not blocking daily use)

- [ ] Tight encoding + JPEG (photographic content, most servers' preference)
- [ ] ExtendedDesktopSize: ask the server to match its resolution to our window
- [ ] Scaling toggle (fit-to-window vs 1:1)
- [ ] TLS / VeNCrypt security types
- [x] Apple DH auth (macOS Screen Sharing offers type 30, not VNC auth)
- [ ] Multi-monitor awareness

## Deliberately not doing

- Session recording, file transfer, chat — scope creep until the viewer is excellent.
- Anything that extends the seance gimmick beyond quips + palette (see CLAUDE.md).
