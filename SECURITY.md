# Seance Security Stance

This document is the security north star for Seance. It is not a checklist to
complete once; it is the standard future features are measured against.

Seance is a remote administration tool. That means security is not an add-on or
a post-launch cleanup phase. The product only works if it is visibly,
deliberately on the operator's side: local-first, consent-driven, observable,
auditable, and honest about the limits of raw VNC compatibility mode.

## Core Position

Seance turns the user's authenticated remote session into a supervised control
surface. The assistant, script, or external client never becomes the authority.
The human operator's live Seance session is the authority boundary.

Security decisions should preserve these properties:

- **Consent**: actions are allowed because the operator approved them, not
  because an integration found a shortcut.
- **Visibility**: the operator can see what is happening while it happens.
- **Auditability**: important actions leave a durable, reviewable trail.
- **Containment**: capabilities are scoped to the intended session, tool, and
  time window.
- **Honesty**: raw VNC compatibility mode is labeled honestly rather than
  dressed up as something stronger.

If a feature weakens one of these properties, it needs an explicit design review
before implementation.

## Compatibility Mode

Seance works with ordinary VNC servers. Its job is universal reach: Windows,
macOS Screen Sharing, TigerVNC, RealVNC, and other existing servers.

Security stance:

- Treat raw VNC as best-effort remote access whose security depends on the
  server, network, and chosen VNC security type.
- Show the user an honest posture badge rather than implying encryption or
  enterprise-grade authentication where it does not exist.
- Preserve compatibility, but do not add fake assurances around legacy
  protocols.
- Prefer safer defaults where the protocol permits it, such as authenticated
  security types over `None` when credentials are supplied.

Compatibility mode may be useful and responsible, but it is not the place to
promise guarantees the underlying protocol cannot keep.

## Agent Bridge Rules

The Agent Bridge is a supervised administration interface. It must never become
covert automation.

Required properties:

- The MCP endpoint binds locally by default and must not be network-exposed by
  accident.
- Bearer tokens stay out of renderer state whenever possible.
- Tool calls are scoped to the active or explicitly pinned session. The agent
  may retarget among open tabs (`switch_tab`) without moving the operator's
  view, and may open a new tab only to an operator-saved host
  (`open_saved_host`). Both retarget tools override the operator's chosen
  tab, so they auto-approve (autonomous or allow-listed) only when the
  operator set the target to "Any tab"; otherwise each call asks. Stored
  credentials go from the OS credential store to the handshake without
  reaching the agent or the renderer.
- Any retarget, by the agent or the operator, clears the 15-minute
  background-tab acknowledgement; it is re-accepted for the new target.
- Ask-every-call is the default consent mode.
- Allow-list and autonomous modes are explicit operator choices, scoped to the
  current session posture.
- Autonomous permission must not silently persist across app restarts.
- Background actions require backend-enforced acknowledgement when the operator
  is not watching the target tab: either a 15-minute acknowledgement, or the
  explicit "Any tab" target setting. That setting is audited when
  turned on or off, and does not persist across restarts.
- Every tool call emits live activity and an audit entry.
- Sensitive free-text arguments are redacted before they hit the audit log.
- Audit entries are hash-chained so tampering is detectable.

When adding a new Agent Bridge tool, answer these questions before writing code:

- What is the smallest useful capability this tool needs?
- Is it read-only, input-like, state-changing, destructive, or secret-bearing?
- Should it ever be eligible for allow-list mode?
- What exact arguments and result fields are safe to audit?
- What must be redacted, summarized, or omitted?
- Does it act on the active session, the pinned session, or a named resource?
- What should happen if the target is backgrounded?
- What user-visible activity should appear while it runs?
- What are the timeout, size, and rate limits?

If the answers are unclear, design the tool as ask-only and narrow.

## Renderer and Tauri Boundary

The renderer is UI, not the trust root. A compromised renderer should not be
able to steal long-lived secrets or silently drive hidden machines.

Rules:

- Keep secrets in Rust, OS credential stores, or native APIs whenever practical.
- Do not return saved passwords, MCP bearer tokens, or setup commands containing
  tokens to renderer JavaScript.
- Prefer native Rust clipboard operations for sensitive copy/read flows.
- Keep Tauri command capabilities narrow and purpose-specific.
- Commands that inject input into a remote machine should only affect the active
  visible tab unless routed through the audited Agent Bridge path.
- Backend checks must enforce security decisions. UI state is helpful feedback,
  not an authorization boundary.
- Keep the content security policy strict. Avoid adding broad `unsafe-*`,
  external script, or broad network allowances.

Manual first-time password entry is currently still a renderer form field, with
the value cleared as soon as a connect attempt starts. A future native password
entry flow should be considered if first-time password exposure becomes a
priority.

## Secret Handling

Default posture:

- Store saved host passwords in the OS credential store.
- Never store passwords in `settings.json`, localStorage, or logs.
- Minimize secret lifetime in memory.
- Do not include secrets in errors, audit logs, events, or UI state snapshots.
- Use copy-to-clipboard flows carefully and audit sensitive token-copy actions.
- Rotate local bridge tokens when requested and make rotation visible to the
  operator.

When a feature needs a secret, prefer this order:

1. OS credential store or native secure storage.
2. Short-lived Rust memory.
3. Renderer memory only for direct user entry, cleared immediately.
4. Never: persistent renderer storage, logs, audit payloads, URLs, or command
   history.

## Audit and Logs

Audit exists for accountability, not voyeurism. Capture the fact and shape of an
action without recording sensitive contents unnecessarily.

Rules:

- Record timestamp, actor identity when known, tool/command, target session,
  decision, result class, and relevant non-sensitive metadata.
- Redact passwords, tokens, clipboard text, typed text, and file contents unless
  there is a specific reviewed need.
- Hash-chain audit entries.
- Keep audit writes backend-side.
- Treat log rotation, export, and at-rest protection as product policy, not
  incidental implementation details.

Open policy decisions:

- Audit retention duration.
- Local export format and integrity verification UX.
- Whether audit logs should be encrypted at rest beyond OS profile protection.

## Transport and Protocol Limits

Anything parsing a remote or local protocol must assume hostile input.

Rules:

- Bound all server-controlled allocations.
- Validate rectangle, cursor, framebuffer, clipboard, compressed payload, and
  length fields before allocation or decode.
- Apply request header, body, timeout, and rate limits to local servers.
- Read request bodies only after authentication where possible.
- Reject browser-originated MCP requests.
- Prefer local-only transports. Consider Unix sockets or named pipes where they
  materially reduce exposure and remain practical cross-platform.
- Do not treat loopback alone as authentication. Loopback plus an unguessable
  bearer token is the current minimum.

## Feature Design Checklist

Before merging a feature that can observe, control, authenticate, persist, or
transmit session data, verify:

- What is the trust boundary?
- What is the worst thing a compromised renderer could do through this feature?
- What is the worst thing a malicious VNC server could send?
- What is the worst thing a local process with access to the MCP endpoint could
  attempt?
- Does the backend enforce the decision, or only the UI?
- Are secrets kept out of renderer state, localStorage, settings, URLs, logs,
  audit entries, and events?
- Are size, time, rate, and lifetime limits explicit?
- Does the operator get useful live visibility?
- Does the audit trail capture accountability without capturing secrets?

If a feature cannot satisfy these questions yet, ship the narrower version.

## Defaults

Secure defaults beat configurable footguns.

- Default consent mode: ask.
- Default bridge bind: local-only.
- Default action scope: active visible session.
- Default persistence: no secrets outside OS credential storage.
- Default audit behavior: record metadata, redact sensitive contents.
- Default response to uncertainty: prompt, narrow scope, or refuse the action.

Configuration can expose advanced options later, but dangerous states should be
hard to reach by accident and obvious when active.

## Documentation Standard

Security-sensitive changes should update the relevant doc at the same time as
the code:

- `SECURITY.md` for principles or stance changes.
- `ROADMAP.md` for future security work.
- `README.md` for user-visible current behavior.

Avoid security theater. Prefer precise statements about what Seance does,
does not do, and plans to do next.
