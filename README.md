# Seance

A modern, cross-platform VNC client for people who are tired of typing
30-character passwords into lab machines by hand.

## Why

Every free VNC client is some combination of ugly, abandoned, or
single-platform. Seance is a Tauri app (Rust core, webview UI) that runs on
Windows and macOS, with an in-house RFB protocol implementation rather than a
libvncclient wrapper. Owning the protocol and input path is the point.

## The Headline Feature

**Paste as keystrokes** (`Ctrl+Shift+V`): takes your local clipboard and types
it on the remote as synthesized RFB `KeyEvent`s. Because it never touches VNC
clipboard sync, it works anywhere keystrokes work: login screens, lock screens,
password fields, consoles, and hosts with no helper agent running.

There is also a **Type text...** box for sending arbitrary text without touching
the clipboard, plus one-click Ctrl+Alt+Del.

## Agent Bridge

Seance exposes a local MCP server so an AI assistant can observe and operate the
user's authenticated remote session under human supervision. The assistant does
not connect to the remote host directly; it calls tools on the Seance client,
which already holds the user's live session. Consent prompts, live activity,
and append-only audit logging are core architecture, not optional settings.
The standing security principles are documented in [SECURITY.md](SECURITY.md).

The bridge is agentless and works against ordinary VNC servers with no host
install. Tools are built on client primitives: `screenshot`, `type_text`,
`key_combo`, `move_pointer`, `click`, `scroll`, `get_clipboard`, and
`set_clipboard`. Tab tools let the agent see and pick its target: `list_tabs`,
`switch_tab` (retargets the agent without changing your view),
`list_saved_hosts`, and `open_saved_host` (connects to a saved host in a
background tab). The MCP endpoint binds to `127.0.0.1`, uses a bearer token
stored in the OS credential store, and gates every tool call through
ask / allow-list / autonomous consent policy.

## Current Status

Field-tested against Windows, macOS Screen Sharing, and Linux/TigerVNC hosts on
LAN and VPN. Works today:

- RFB 3.8 handshake
- Security types: None, legacy VNC auth, and Apple DH auth for macOS Screen
  Sharing with a normal macOS username and password
- Encodings: Raw, ZRLE, CopyRect, DesktopSize, and Cursor pseudo-encoding
- Full keyboard, mouse, and wheel forwarding via X11 keysym mapping
- Paste-as-keystrokes, type-text box, and Ctrl+Alt+Del
- Remote-to-local clipboard sync on standard VNC servers
- Standard ClientCutText remote clipboard writes where the server supports it
- Fit-to-window scaling with letterbox-correct pointer mapping
- Binary framebuffer transport over a token-gated loopback WebSocket
- Multi-session tabs; hidden tabs pause framebuffer updates
- Agent Bridge tab targeting via active or pinned session
- Saved hosts with metadata in `settings.json` and passwords in the OS
  credential store
- Reconnect prompt for dropped sessions
- Connect quips and an aubergine dark theme

Security hardening already landed:

- Server-controlled framebuffer, rect, cursor, clipboard, and ZRLE allocation
  sizes are bounded
- MCP HTTP requests require header-only bearer auth, reject browser `Origin`
  requests, and enforce header/body/time/rate limits
- Autonomous consent is not restored across app launches
- Background autonomous Agent Bridge actions require a live operator
  acknowledgement
- Sensitive Agent Bridge text arguments are redacted in a hash-chained audit log
- Sessions surface an honest security posture badge for raw VNC compatibility
  mode
- Strict renderer CSP is enabled
- Saved host passwords are consumed backend-side in normal reconnect flows
- The MCP token and setup command are copied from Rust instead of being returned
  to renderer JavaScript
- Renderer-originated input commands are scoped to the active visible tab

Still open:

- Audit log retention/export/at-rest protection policy
- Native manual-password entry flow consideration
- Unix socket / named pipe MCP transport consideration
- Configurable MCP port
- stdio transport shim for stdio-only MCP clients
- Agent Bridge input polish: drag, batched sequences, focus helper, clipboard
  freshness signal
- Tight/JPEG encoding, TLS/VeNCrypt, multi-monitor, and ExtendedDesktopSize
- Verified green CI matrix for Windows and macOS

## Development

```sh
npm install
npm run tauri dev
```

Requires Rust, Node, and the platform build toolchain. On Windows, use the MSVC
Rust toolchain.

Local checks:

```sh
npm run build
cd src-tauri
cargo test
```

Builds are done and tested locally for now. A GitHub Actions workflow
(`.github/workflows/build.yml`) is committed, but it is not yet treated as the
source of truth until the matrix is verified green.

## Licensing

Seance is free and open source under [Apache-2.0](LICENSE).
