//! Agent Bridge (agentless).
//!
//! Exposes a local MCP *server* so any MCP-speaking assistant (Claude Code,
//! Claude Desktop, Codex, …) can observe and drive the user's *current*
//! authenticated session. It is built entirely on primitives the client
//! already has — framebuffer screenshot and the input path — so it works
//! against any VNC server with no host install.
//!
//! Security is architecture here, not settings:
//!   - **Local-only transport.** Binds 127.0.0.1 on a stable port (falling
//!     back to a random one if taken) with a bearer token that persists in
//!     the OS credential store, so an MCP client registration survives
//!     restarts. Never exposed to the network; the operator can rotate the
//!     token from the panel at any time.
//!   - **Consent by default.** Every `tools/call` passes the consent gate:
//!     ask-every-call (default) / per-tool allow-list / autonomous. An "ask"
//!     call blocks on the operator's approval and times out denied.
//!   - **Live visibility.** Each call emits `agent-activity` for the in-client
//!     panel, so the human watches the work in real time.
//!   - **Append-only audit.** Every invocation is written to `agent-audit.jsonl`
//!     (timestamp, agent, tool, args, decision, result).
//!   - **Session scoping.** Screen and input tools reach only the pinned (or
//!     active) tab. The agent may retarget among open tabs, and may open a new
//!     tab only to a host the operator saved, with stored credentials that
//!     never leave Rust.

mod keys;

use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Manager};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::{timeout, Duration};

const CONSENT_TIMEOUT: Duration = Duration::from_secs(120);
const PROTOCOL_VERSION: &str = "2024-11-05";

/// Hard limits on the local HTTP surface. Loopback + a 128-bit bearer token is
/// the real boundary, but these bound a hostile *local* process and keep an
/// unauthenticated caller from tying up memory or a socket.
const MAX_HEAD: usize = 64 << 10; // 64 KB of request headers
const MAX_BODY: usize = 1 << 20; // 1 MB JSON-RPC body
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const RATE_WINDOW: Duration = Duration::from_secs(60);
const RATE_MAX_REQUESTS: usize = 240;

/// Constant-time byte comparison, so token validation doesn't leak a match
/// prefix through response timing. Length is not secret (the token is 32 hex).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[derive(Default)]
struct RateLimit {
    hits: VecDeque<std::time::Instant>,
}

impl RateLimit {
    fn allow(&mut self) -> bool {
        let now = std::time::Instant::now();
        while self
            .hits
            .front()
            .is_some_and(|t| now.duration_since(*t) > RATE_WINDOW)
        {
            self.hits.pop_front();
        }
        if self.hits.len() >= RATE_MAX_REQUESTS {
            return false;
        }
        self.hits.push_back(now);
        true
    }
}

/// Default MCP port. Stable so an agent registration keeps working across
/// restarts; if something else holds it we fall back to an OS-assigned port
/// (the panel always shows the real endpoint).
const DEFAULT_PORT: u16 = 47313;
const KEYRING_SERVICE: &str = "seance-agent-bridge";

/// The bearer token, loaded from the OS credential store or minted on first
/// run. Falls back to a session-only token if the store is unavailable —
/// the bridge still works, it just won't survive a restart.
fn load_or_create_token() -> String {
    let entry = keyring::Entry::new(KEYRING_SERVICE, "mcp-token");
    if let Ok(e) = &entry {
        if let Ok(t) = e.get_password() {
            if t.len() == 32 && t.bytes().all(|b| b.is_ascii_hexdigit()) {
                return t;
            }
        }
    }
    let token = format!("{:032x}", rand::random::<u128>());
    if let Ok(e) = &entry {
        let _ = e.set_password(&token);
    }
    token
}

#[derive(Clone)]
pub enum ConsentMode {
    /// Prompt the operator for every call. Default.
    Ask,
    /// Auto-approve tools on the list; prompt for the rest.
    AllowList(HashSet<String>),
    /// Auto-approve everything for this session.
    Autonomous,
}

/// How long an operator's "I accept background autonomous actions"
/// acknowledgement stays valid before it must be re-armed.
const BG_ACK_TTL: Duration = Duration::from_secs(15 * 60);

struct Inner {
    endpoint: String,
    token: Mutex<String>,
    app: AppHandle,
    consent: Mutex<ConsentMode>,
    pending: Mutex<HashMap<u64, oneshot::Sender<bool>>>,
    next_id: AtomicU64,
    /// Identity of the connected agent, captured at `initialize`. Single agent
    /// at a time — reasonable for a supervised local bridge.
    agent_name: Mutex<String>,
    audit_path: PathBuf,
    audit_tip: Mutex<String>,
    rate: Mutex<RateLimit>,
    /// Expiry of the operator's acknowledgement for autonomous actions on a
    /// background (unwatched) tab. Enforced in `decide`, not just the UI.
    bg_ack_until: Mutex<Option<std::time::Instant>>,
    /// Operator setting: auto-approval also covers tabs they aren't viewing —
    /// no expiry, survives agent retargets. Session-only, like autonomous.
    bg_all: AtomicBool,
    /// Serializes `open_saved_host`, so two concurrent calls for one host share
    /// a tab instead of both opening a connection.
    open_lock: tokio::sync::Mutex<()>,
}

#[derive(Clone)]
pub struct AgentBridge(Arc<Inner>);

impl AgentBridge {
    pub async fn start(app: AppHandle) -> Result<Self, crate::rfb::Error> {
        let listener = match TcpListener::bind(("127.0.0.1", DEFAULT_PORT)).await {
            Ok(l) => l,
            Err(_) => TcpListener::bind(("127.0.0.1", 0)).await?,
        };
        let port = listener.local_addr()?.port();
        let token = load_or_create_token();
        let endpoint = format!("http://127.0.0.1:{port}/mcp");

        let audit_path = app
            .path()
            .app_data_dir()
            .map(|d| d.join("agent-audit.jsonl"))
            .unwrap_or_else(|_| PathBuf::from("agent-audit.jsonl"));
        if let Some(parent) = audit_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let audit_tip = load_audit_tip(&audit_path);

        let bridge = AgentBridge(Arc::new(Inner {
            endpoint,
            token: Mutex::new(token),
            app,
            consent: Mutex::new(ConsentMode::Ask),
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            agent_name: Mutex::new("unknown agent".into()),
            audit_path,
            audit_tip: Mutex::new(audit_tip),
            rate: Mutex::new(RateLimit::default()),
            bg_ack_until: Mutex::new(None),
            bg_all: AtomicBool::new(false),
            open_lock: tokio::sync::Mutex::new(()),
        }));

        // dev affordance: surface the local endpoint + token so a developer can
        // wire up an agent (and so smoke tests can reach it). Never in release.
        #[cfg(debug_assertions)]
        eprintln!(
            "[agent-bridge] {} (Authorization: Bearer {})",
            bridge.0.endpoint,
            bridge.0.token.lock().unwrap()
        );

        let accept = bridge.clone();
        tauri::async_runtime::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let b = accept.clone();
                tauri::async_runtime::spawn(async move {
                    let _ = b.handle_conn(stream).await;
                });
            }
        });

        Ok(bridge)
    }

    pub fn endpoint(&self) -> String {
        self.0.endpoint.clone()
    }

    pub fn token(&self) -> String {
        self.0.token.lock().unwrap().clone()
    }

    /// Mint and persist a new bearer token, invalidating the old one for all
    /// future requests. Audited: rotation is a security-relevant act.
    pub fn rotate_token(&self) -> String {
        let token = format!("{:032x}", rand::random::<u128>());
        if let Ok(e) = keyring::Entry::new(KEYRING_SERVICE, "mcp-token") {
            let _ = e.set_password(&token);
        }
        *self.0.token.lock().unwrap() = token.clone();
        self.audit_note("operator rotated the MCP bearer token");
        token
    }

    pub fn set_consent(&self, mode: ConsentMode) {
        *self.0.consent.lock().unwrap() = mode;
    }

    /// Current consent policy as `("ask"|"allowlist"|"autonomous", allow-list)`
    /// — the wire shape the panel and the settings file share.
    pub fn consent_strings(&self) -> (String, Vec<String>) {
        match &*self.0.consent.lock().unwrap() {
            ConsentMode::Ask => ("ask".into(), Vec::new()),
            ConsentMode::AllowList(s) => {
                let mut allow: Vec<String> = s.iter().cloned().collect();
                allow.sort();
                ("allowlist".into(), allow)
            }
            ConsentMode::Autonomous => ("autonomous".into(), Vec::new()),
        }
    }

    /// Resolve a pending consent prompt from the UI.
    pub fn resolve_consent(&self, id: u64, approved: bool) {
        if let Some(tx) = self.0.pending.lock().unwrap().remove(&id) {
            let _ = tx.send(approved);
        }
    }

    /// The operator accepts responsibility for autonomous actions on a tab they
    /// aren't watching. Arms a time-limited, backend-held acknowledgement that
    /// `decide` requires — the UI banner is a prompt, this is the enforcement.
    pub fn accept_background(&self) {
        *self.0.bg_ack_until.lock().unwrap() = Some(std::time::Instant::now() + BG_ACK_TTL);
        self.audit_note(
            "operator accepted responsibility: autonomous agent actions on a pinned background tab (15m)",
        );
    }

    /// Let auto-approved calls (autonomous / allow-list) run on every tab, not
    /// just the one being viewed. Turning it on *is* the operator's standing
    /// acknowledgement, so both directions are audited.
    pub fn set_background_autonomy(&self, on: bool) {
        self.0.bg_all.store(on, Ordering::SeqCst);
        self.audit_note(if on {
            "operator allowed auto-approved agent actions on all tabs, including tabs not being viewed"
        } else {
            "operator limited auto-approved agent actions to the viewed tab"
        });
    }

    pub fn background_autonomy(&self) -> bool {
        self.0.bg_all.load(Ordering::SeqCst)
    }

    /// Drop any background acknowledgement: it was given for one target tab
    /// and never carries over to another.
    pub fn clear_background_ack(&self) {
        *self.0.bg_ack_until.lock().unwrap() = None;
    }

    fn bg_ack_valid(&self) -> bool {
        matches!(*self.0.bg_ack_until.lock().unwrap(), Some(t) if t > std::time::Instant::now())
    }

    // --- HTTP / JSON-RPC plumbing -------------------------------------------

    async fn handle_conn(&self, mut stream: TcpStream) -> std::io::Result<()> {
        // Read the headers under a deadline so a stalled/slowloris caller can't
        // pin the connection.
        let Ok(Some((method, headers, leftover))) =
            timeout(REQUEST_TIMEOUT, read_head(&mut stream)).await
        else {
            return write_response(&mut stream, 400, "Bad Request", b"").await;
        };

        // Reject anything with an Origin: a real MCP client never sets it; a web
        // page attacking the loopback port always does. This blocks DNS-rebinding
        // / CSRF against 127.0.0.1 before auth is even considered.
        if headers.contains_key("origin") {
            return write_response(&mut stream, 403, "Forbidden", b"").await;
        }

        // Auth: Authorization: Bearer <token> only (no token-in-URL — URLs leak
        // into logs and history), compared in constant time.
        let token = self.0.token.lock().unwrap().clone();
        let bearer = headers
            .get("authorization")
            .and_then(|v| {
                v.strip_prefix("Bearer ")
                    .or_else(|| v.strip_prefix("bearer "))
            })
            .unwrap_or("");
        if !ct_eq(bearer.as_bytes(), token.as_bytes()) {
            return write_response(&mut stream, 401, "Unauthorized", b"").await;
        }
        if !self.0.rate.lock().unwrap().allow() {
            return write_response(&mut stream, 429, "Too Many Requests", b"").await;
        }
        if method != "POST" {
            // no server-initiated stream; a GET for SSE is simply unsupported
            return write_response(&mut stream, 405, "Method Not Allowed", b"").await;
        }

        // Bounded body, read only after auth passes.
        let clen: usize = headers
            .get("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        if clen > MAX_BODY {
            return write_response(&mut stream, 413, "Payload Too Large", b"").await;
        }
        let Ok(Some(body)) = timeout(REQUEST_TIMEOUT, read_body(&mut stream, leftover, clen)).await
        else {
            return write_response(&mut stream, 400, "Bad Request", b"").await;
        };

        let Ok(req) = serde_json::from_slice::<Value>(&body) else {
            return write_json(
                &mut stream,
                &err_envelope(&Value::Null, -32700, "parse error"),
            )
            .await;
        };

        // notifications carry no id and expect no body
        if req.get("id").is_none() {
            return write_response(&mut stream, 202, "Accepted", b"").await;
        }
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let rpc_method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = req.get("params").cloned().unwrap_or(json!({}));

        let envelope = match rpc_method {
            "initialize" => {
                if let Some(n) = params
                    .get("clientInfo")
                    .and_then(|c| c.get("name"))
                    .and_then(|n| n.as_str())
                {
                    *self.0.agent_name.lock().unwrap() = n.to_string();
                }
                ok_envelope(
                    &id,
                    json!({
                        "protocolVersion": PROTOCOL_VERSION,
                        "capabilities": { "tools": {} },
                        "serverInfo": {
                            "name": "seance-agent-bridge",
                            "version": env!("CARGO_PKG_VERSION")
                        }
                    }),
                )
            }
            "ping" => ok_envelope(&id, json!({})),
            "tools/list" => ok_envelope(&id, json!({ "tools": tool_specs() })),
            "tools/call" => ok_envelope(&id, self.call_tool(&params).await),
            other => err_envelope(&id, -32601, &format!("method not found: {other}")),
        };

        write_json(&mut stream, &envelope).await
    }

    // --- Tool dispatch -------------------------------------------------------

    async fn call_tool(&self, params: &Value) -> Value {
        let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
        let args = params.get("arguments").cloned().unwrap_or(json!({}));
        let agent = self.0.agent_name.lock().unwrap().clone();
        let state = self.0.app.state::<crate::AppState>();

        // session scoping: screen tools act on the operator's pinned tab (or
        // the active tab if none is pinned). Tab tools act on the bridge's own
        // targeting instead, so they don't need a session. `background` = the
        // operator isn't viewing the tab the call touches.
        let (tab, session, background) = if is_tab_tool(name) {
            let tab = match name {
                "switch_tab" => args.get("tab").and_then(|t| t.as_u64()).map(|t| t as u32),
                _ => None,
            };
            (tab, None, tab.is_some_and(|t| state.is_background(t)))
        } else {
            let Some((tab, session, background)) = state.agent_target() else {
                let _ = self.0.app.emit(
                    "agent-activity",
                    json!({ "phase": "error", "tool": name, "error": "no session", "ts": now_ms() }),
                );
                return tool_error(
                    "no session for the agent — open a host (open_saved_host) or pin a tab in the Agent Bridge panel",
                );
            };
            (Some(tab), Some(session), background)
        };
        // A switch to a tab that isn't open fails now, not after a prompt.
        if name == "switch_tab" && !tab.is_some_and(|t| state.has_tab(t)) {
            return self.reject(
                &agent,
                name,
                &args,
                "switch_tab requires the `tab` id of an open tab (see list_tabs)",
            );
        }
        // Resolve the saved host *before* consent, so the operator approves the
        // actual address rather than whatever string the agent sent.
        let saved = if name == "open_saved_host" {
            let hosts = crate::settings::load(&self.0.app).hosts;
            let group = Some(arg_str(&args, "group")).filter(|g| !g.is_empty());
            match find_saved_host(&hosts, arg_str(&args, "name"), group) {
                Ok(h) => Some(h.clone()),
                Err(e) => return self.reject(&agent, name, &args, &e),
            }
        } else {
            None
        };
        // what the call reaches beyond the tab, recorded in the audit
        let mut target = saved
            .as_ref()
            .map(|h| json!({ "name": h.name, "host": h.host, "port": h.port }));
        // what the consent prompt names when the call isn't about a tab
        let detail = match name {
            "open_saved_host" => saved
                .as_ref()
                .map(|h| format!("{} ({}:{})", h.name, h.host, h.port)),
            "list_saved_hosts" => Some("saved hosts".to_string()),
            "list_tabs" => Some("open tabs".to_string()),
            _ => None,
        };

        let _ = self.0.app.emit(
            "agent-activity",
            json!({ "phase": "requested", "agent": agent, "tool": name, "args": args,
                    "tab": tab, "background": background, "ts": now_ms() }),
        );

        if !self.decide(name, tab, background, detail.as_deref()).await {
            self.audit(&agent, name, &args, tab, background, "denied", "", target);
            let _ = self.0.app.emit(
                "agent-activity",
                json!({ "phase": "denied", "tool": name, "tab": tab, "ts": now_ms() }),
            );
            return tool_error("denied by operator");
        }

        let result = match &session {
            Some(session) => self.execute(name, &args, session).await,
            None => match self.execute_tab_tool(name, &args, saved.as_ref()).await {
                Ok((v, Some(now_targets))) => {
                    // record which tab the agent ended up driving
                    let t = target.get_or_insert_with(|| json!({}));
                    t["tab"] = json!(now_targets);
                    Ok(v)
                }
                other => other.map(|(v, _)| v),
            },
        };
        match result {
            Ok(v) => {
                self.audit(
                    &agent, name, &args, tab, background, "approved", "ok", target,
                );
                let _ = self.0.app.emit(
                    "agent-activity",
                    json!({ "phase": "completed", "tool": name, "tab": tab,
                            "background": background, "ts": now_ms() }),
                );
                v
            }
            Err(e) => {
                self.audit(
                    &agent,
                    name,
                    &args,
                    tab,
                    background,
                    "approved",
                    &format!("error: {e}"),
                    target,
                );
                let _ = self.0.app.emit(
                    "agent-activity",
                    json!({ "phase": "error", "tool": name, "tab": tab, "error": e, "ts": now_ms() }),
                );
                tool_error(&e)
            }
        }
    }

    /// Refuse a call that can't be valid before asking the operator about it.
    /// Audited as `rejected`, with no tab, since none was resolved.
    fn reject(&self, agent: &str, tool: &str, args: &Value, error: &str) -> Value {
        self.audit(
            agent,
            tool,
            args,
            None,
            false,
            "rejected",
            &format!("error: {error}"),
            None,
        );
        let _ = self.0.app.emit(
            "agent-activity",
            json!({ "phase": "error", "tool": tool, "error": error, "ts": now_ms() }),
        );
        tool_error(error)
    }

    async fn decide(
        &self,
        tool: &str,
        tab: Option<u32>,
        background: bool,
        detail: Option<&str>,
    ) -> bool {
        // Retargeting overrides the tab the operator chose. Only "Any tab"
        // hands that choice to the agent; otherwise every retarget is asked.
        if RETARGET_TOOLS.contains(&tool) && !self.background_autonomy() {
            return self.ask(tool, tab, detail).await;
        }
        let auto = match &*self.0.consent.lock().unwrap() {
            ConsentMode::Autonomous => true,
            ConsentMode::AllowList(set) => set.contains(tool),
            ConsentMode::Ask => false,
        };
        if auto {
            // Never auto-approve an action on a tab the operator isn't watching
            // without a backend-held acknowledgement — a live 15-minute one, or
            // the standing all-tabs setting — even in autonomous or allow-list
            // mode. Otherwise fall through to an explicit prompt.
            if background && !self.bg_ack_valid() && !self.background_autonomy() {
                return self.ask(tool, tab, detail).await;
            }
            return true;
        }
        self.ask(tool, tab, detail).await
    }

    async fn ask(&self, tool: &str, tab: Option<u32>, detail: Option<&str>) -> bool {
        let id = self.0.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        self.0.pending.lock().unwrap().insert(id, tx);
        let _ = self.0.app.emit(
            "agent-consent-request",
            json!({
                "id": id, "tool": tool, "tab": tab, "detail": detail,
                "agent": self.0.agent_name.lock().unwrap().clone(),
                "ts": now_ms()
            }),
        );
        let approved = matches!(timeout(CONSENT_TIMEOUT, rx).await, Ok(Ok(true)));
        self.0.pending.lock().unwrap().remove(&id);
        approved
    }

    async fn execute(
        &self,
        name: &str,
        args: &Value,
        session: &crate::rfb::SessionHandle,
    ) -> Result<Value, String> {
        let (fbw, fbh) = session.dims();
        let clamp_x = |v: i64| v.clamp(0, fbw.saturating_sub(1) as i64) as u16;
        let clamp_y = |v: i64| v.clamp(0, fbh.saturating_sub(1) as i64) as u16;
        let arg_i = |k: &str| args.get(k).and_then(|v| v.as_i64());

        match name {
            "screenshot" => {
                let png = session.screenshot_png().map_err(|e| e.to_string())?;
                let b64 = base64::engine::general_purpose::STANDARD.encode(&png);
                Ok(json!({
                    "content": [{ "type": "image", "data": b64, "mimeType": "image/png" }]
                }))
            }
            "type_text" => {
                let text = arg_str(args, "text");
                session.type_text(text).await.map_err(|e| e.to_string())?;
                Ok(tool_ok(&format!(
                    "typed {} characters",
                    text.chars().count()
                )))
            }
            "key_combo" => {
                let keys = args
                    .get("keys")
                    .and_then(|k| k.as_array())
                    .ok_or("key_combo requires a `keys` array")?;
                let syms: Vec<u32> = keys
                    .iter()
                    .map(|k| {
                        k.as_str()
                            .and_then(keys::name_to_keysym)
                            .ok_or_else(|| format!("unknown key: {k}"))
                    })
                    .collect::<Result<_, _>>()?;
                for s in &syms {
                    session
                        .send_key(*s, true)
                        .await
                        .map_err(|e| e.to_string())?;
                }
                for s in syms.iter().rev() {
                    session
                        .send_key(*s, false)
                        .await
                        .map_err(|e| e.to_string())?;
                }
                Ok(tool_ok("key combo sent"))
            }
            "move_pointer" => {
                let (x, y) = (
                    clamp_x(arg_i("x").unwrap_or(0)),
                    clamp_y(arg_i("y").unwrap_or(0)),
                );
                session
                    .send_pointer(x, y, 0)
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(tool_ok(&format!("pointer at {x},{y}")))
            }
            "click" => {
                let (x, y) = (
                    clamp_x(arg_i("x").unwrap_or(0)),
                    clamp_y(arg_i("y").unwrap_or(0)),
                );
                let mask = match arg_str(args, "button") {
                    "right" => 4u8,
                    "middle" => 2u8,
                    _ => 1u8,
                };
                let times = if args
                    .get("double")
                    .and_then(|d| d.as_bool())
                    .unwrap_or(false)
                {
                    2
                } else {
                    1
                };
                session
                    .send_pointer(x, y, 0)
                    .await
                    .map_err(|e| e.to_string())?;
                for _ in 0..times {
                    session
                        .send_pointer(x, y, mask)
                        .await
                        .map_err(|e| e.to_string())?;
                    session
                        .send_pointer(x, y, 0)
                        .await
                        .map_err(|e| e.to_string())?;
                }
                Ok(tool_ok(&format!("clicked {x},{y}")))
            }
            "scroll" => {
                let (x, y) = (
                    clamp_x(arg_i("x").unwrap_or(0)),
                    clamp_y(arg_i("y").unwrap_or(0)),
                );
                let bit = if arg_str(args, "direction") == "up" {
                    8u8
                } else {
                    16u8
                };
                let amount = arg_i("amount").unwrap_or(3).clamp(1, 50);
                for _ in 0..amount {
                    session
                        .send_pointer(x, y, bit)
                        .await
                        .map_err(|e| e.to_string())?;
                    session
                        .send_pointer(x, y, 0)
                        .await
                        .map_err(|e| e.to_string())?;
                }
                Ok(tool_ok(&format!("scrolled {}", arg_str(args, "direction"))))
            }
            "get_clipboard" => Ok(tool_ok(&session.remote_clipboard())),
            "set_clipboard" => {
                let text = arg_str(args, "text");
                session
                    .set_remote_clipboard(text)
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(tool_ok("remote clipboard set"))
            }
            other => Err(format!("unknown tool: {other}")),
        }
    }

    /// Tools that choose which tab the agent drives rather than touching a
    /// remote screen. None of them move the operator's view. Returns the tool
    /// result plus the tab the agent now targets, when the call changed it.
    /// `saved` is the host `open_saved_host` resolved before consent.
    async fn execute_tab_tool(
        &self,
        name: &str,
        args: &Value,
        saved: Option<&crate::settings::SavedHost>,
    ) -> Result<(Value, Option<u32>), String> {
        let app = &self.0.app;
        let state = app.state::<crate::AppState>();
        match name {
            "list_tabs" => Ok((tool_json(&json!(state.tab_list())), None)),
            "switch_tab" => {
                let tab = args
                    .get("tab")
                    .and_then(|t| t.as_u64())
                    .ok_or("switch_tab requires a `tab` id (see list_tabs)")?
                    as u32;
                state.pin(tab)?;
                self.retargeted(tab);
                crate::kick_streaming(&state).await;
                Ok((tool_ok(&format!("agent now targets tab {tab}")), Some(tab)))
            }
            "list_saved_hosts" => {
                let hosts: Vec<Value> = crate::settings::load(app)
                    .hosts
                    .iter()
                    .map(|h| {
                        json!({ "name": h.name, "group": h.group, "host": h.host,
                                "port": h.port, "has_password": h.has_password })
                    })
                    .collect();
                Ok((tool_json(&json!(hosts)), None))
            }
            "open_saved_host" => {
                let saved = saved.ok_or("saved host was not resolved")?;
                let _serial = self.0.open_lock.lock().await;
                if let Some(tab) = state.find_tab(&saved.host, saved.port) {
                    state.pin(tab)?;
                    self.retargeted(tab);
                    crate::kick_streaming(&state).await;
                    return Ok((
                        tool_ok(&format!(
                            "{} is already open as tab {tab}; agent now targets it",
                            saved.name
                        )),
                        Some(tab),
                    ));
                }
                // opened as the agent's pinned target, streaming from the start
                let channel = app.state::<crate::frames::FrameChannel>();
                let opened = crate::open_stored_session(
                    app.clone(),
                    &state,
                    &channel,
                    saved.host.clone(),
                    saved.port,
                    saved.username.clone(),
                    crate::Opener::Agent,
                )
                .await?;
                let tab = opened["id"].as_u64().ok_or("connect returned no tab id")? as u32;
                // the webview adds the tab before it learns the new pin
                let _ = app.emit(
                    "agent-session-opened",
                    json!({ "id": tab, "info": opened["info"], "host": saved.host,
                            "port": saved.port, "username": saved.username }),
                );
                self.retargeted(tab);
                Ok((
                    tool_ok(&format!(
                        "opened {} as tab {tab}; agent now targets it",
                        saved.name
                    )),
                    Some(tab),
                ))
            }
            other => Err(format!("unknown tool: {other}")),
        }
    }

    /// The agent moved its own target: tell the panel, and drop any background
    /// acknowledgement — the operator gave it for a different tab.
    fn retargeted(&self, tab: u32) {
        self.clear_background_ack();
        let _ = self.0.app.emit("agent-pinned", json!({ "id": tab }));
    }

    #[allow(clippy::too_many_arguments)]
    fn audit(
        &self,
        agent: &str,
        tool: &str,
        args: &Value,
        tab: Option<u32>,
        background: bool,
        decision: &str,
        result: &str,
        target: Option<Value>,
    ) {
        let mut line = json!({
            "ts": now_ms(), "agent": agent, "tool": tool, "args": redact_args(tool, args),
            "tab": tab, "background": background, "decision": decision, "result": result
        });
        // what a tab tool resolved or switched to (host:port, resulting tab)
        if let Some(t) = target {
            line["target"] = t;
        }
        self.append_audit(line);
    }

    /// Write a free-form note to the audit log (e.g. the operator accepting
    /// responsibility for autonomous actions on a background tab). Also surfaces
    /// it in the live activity feed so the operator can see it landed.
    pub fn audit_note(&self, note: &str) {
        self.append_audit(json!({ "ts": now_ms(), "note": note }));
        let _ = self.0.app.emit(
            "agent-activity",
            json!({ "phase": "note", "note": note, "ts": now_ms() }),
        );
    }

    fn append_audit(&self, mut line: Value) {
        let mut audit_tip = self.0.audit_tip.lock().unwrap();
        let prev_hash = audit_tip.clone();
        if let Some(obj) = line.as_object_mut() {
            obj.insert("prev_hash".into(), json!(prev_hash));
        }
        let canonical = serde_json::to_vec(&line).unwrap_or_default();
        let hash = hex_sha256(&canonical);
        if let Some(obj) = line.as_object_mut() {
            obj.insert("hash".into(), json!(hash.clone()));
        }
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.0.audit_path)
        {
            let _ = writeln!(f, "{line}");
            *audit_tip = hash;
        }
    }
}

// --- MCP tool schemas -------------------------------------------------------

fn tool_specs() -> Value {
    json!([
        {
            "name": "screenshot",
            "description": "Capture the current remote screen as a PNG image.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "type_text",
            "description": "Type text on the remote as synthesized keystrokes. Works on login/lock screens and password fields.",
            "inputSchema": {
                "type": "object",
                "properties": { "text": { "type": "string" } },
                "required": ["text"]
            }
        },
        {
            "name": "key_combo",
            "description": "Press a chord, e.g. [\"ctrl\",\"alt\",\"delete\"] or [\"ctrl\",\"c\"]. Keys are pressed in order and released in reverse.",
            "inputSchema": {
                "type": "object",
                "properties": { "keys": { "type": "array", "items": { "type": "string" } } },
                "required": ["keys"]
            }
        },
        {
            "name": "move_pointer",
            "description": "Move the pointer to remote coordinates.",
            "inputSchema": {
                "type": "object",
                "properties": { "x": { "type": "integer" }, "y": { "type": "integer" } },
                "required": ["x", "y"]
            }
        },
        {
            "name": "click",
            "description": "Click at remote coordinates. button: left|right|middle. Set double:true for a double-click.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "x": { "type": "integer" }, "y": { "type": "integer" },
                    "button": { "type": "string", "enum": ["left", "right", "middle"] },
                    "double": { "type": "boolean" }
                },
                "required": ["x", "y"]
            }
        },
        {
            "name": "scroll",
            "description": "Scroll the wheel at remote coordinates. direction: up|down, amount: wheel clicks.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "x": { "type": "integer" }, "y": { "type": "integer" },
                    "direction": { "type": "string", "enum": ["up", "down"] },
                    "amount": { "type": "integer" }
                },
                "required": ["x", "y", "direction"]
            }
        },
        {
            "name": "get_clipboard",
            "description": "Return the remote clipboard text, as last sent by the remote host.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "set_clipboard",
            "description": "Set the remote clipboard via the standard VNC clipboard channel.",
            "inputSchema": {
                "type": "object",
                "properties": { "text": { "type": "string" } },
                "required": ["text"]
            }
        },
        {
            "name": "list_tabs",
            "description": "List open session tabs: tab id, name, host, whether the operator is viewing it, and which one is the agent's target.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "switch_tab",
            "description": "Make another open tab the agent's target for all screen and input tools. Does not change which tab the operator is viewing.",
            "inputSchema": {
                "type": "object",
                "properties": { "tab": { "type": "integer", "description": "Tab id from list_tabs." } },
                "required": ["tab"]
            }
        },
        {
            "name": "list_saved_hosts",
            "description": "List the operator's saved hosts (name, group, address). These are the hosts open_saved_host can connect to.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "open_saved_host",
            "description": "Connect to a saved host in a new background tab using its stored credentials, and make it the agent's target. If it is already open, retargets to that tab.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "Saved host name (or address) from list_saved_hosts." },
                    "group": { "type": "string", "description": "Group, to disambiguate hosts with the same name." }
                },
                "required": ["name"]
            }
        }
    ])
}

/// Tools that move the agent's target. Auto-approved only under "Any tab".
const RETARGET_TOOLS: &[&str] = &["switch_tab", "open_saved_host"];

/// Tools that manage tab targeting instead of acting on the target session.
fn is_tab_tool(name: &str) -> bool {
    matches!(
        name,
        "list_tabs" | "switch_tab" | "list_saved_hosts" | "open_saved_host"
    )
}

/// Resolve a saved host by name or address (case-insensitive), optionally
/// narrowed by group. Ambiguity is an error, never a guess.
fn find_saved_host<'a>(
    hosts: &'a [crate::settings::SavedHost],
    name: &str,
    group: Option<&str>,
) -> Result<&'a crate::settings::SavedHost, String> {
    let matches: Vec<_> = hosts
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case(name) || h.host.eq_ignore_ascii_case(name))
        .filter(|h| group.is_none_or(|g| h.group.as_deref().unwrap_or("").eq_ignore_ascii_case(g)))
        .collect();
    match matches.as_slice() {
        [one] => Ok(one),
        [] => Err(format!(
            "no saved host named {name:?} — see list_saved_hosts"
        )),
        _ => Err(format!(
            "{} saved hosts match {name:?} — pass `group` to pick one",
            matches.len()
        )),
    }
}

// --- small helpers ----------------------------------------------------------

fn arg_str<'a>(args: &'a Value, key: &str) -> &'a str {
    args.get(key).and_then(|v| v.as_str()).unwrap_or("")
}

fn tool_json(v: &Value) -> Value {
    tool_ok(&serde_json::to_string_pretty(v).unwrap_or_default())
}

fn tool_ok(text: &str) -> Value {
    json!({ "content": [{ "type": "text", "text": text }] })
}

fn tool_error(text: &str) -> Value {
    json!({ "content": [{ "type": "text", "text": text }], "isError": true })
}

/// Redact free-text tool arguments before they hit the audit log — `type_text`
/// and `set_clipboard` carry whatever the agent typed, which can include
/// passwords. Keep the length (useful for review) but not the content.
fn redact_args(tool: &str, args: &Value) -> Value {
    let mut a = args.clone();
    if matches!(tool, "type_text" | "set_clipboard") {
        if let Some(t) = a.get("text").and_then(|v| v.as_str()) {
            let n = t.chars().count();
            a["text"] = json!(format!("<redacted {n} chars>"));
        }
    }
    a
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

fn load_audit_tip(path: &PathBuf) -> String {
    let Ok(text) = std::fs::read_to_string(path) else {
        return String::new();
    };
    text.lines()
        .rev()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find_map(|v| v.get("hash").and_then(|h| h.as_str()).map(str::to_string))
        .unwrap_or_default()
}

fn ok_envelope(id: &Value, result: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({ "jsonrpc": "2.0", "id": id, "result": result })).unwrap_or_default()
}

fn err_envelope(id: &Value, code: i32, message: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "jsonrpc": "2.0", "id": id,
        "error": { "code": code, "message": message }
    }))
    .unwrap_or_default()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Read an HTTP/1.1 request line + headers: (method, lowercased headers, any
/// body bytes already buffered past the header terminator). Bounded by
/// `MAX_HEAD` so a caller can't stream headers forever.
async fn read_head(stream: &mut TcpStream) -> Option<(String, HashMap<String, String>, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_subsequence(&buf, b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > MAX_HEAD {
            return None;
        }
    };

    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let mut lines = head.split("\r\n");
    let method = lines.next()?.split_whitespace().next()?.to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let leftover = buf[header_end + 4..].to_vec();
    Some((method, headers, leftover))
}

/// Read exactly `clen` body bytes, starting from whatever was already buffered.
async fn read_body(stream: &mut TcpStream, mut body: Vec<u8>, clen: usize) -> Option<Vec<u8>> {
    let mut tmp = [0u8; 4096];
    while body.len() < clen {
        let n = stream.read(&mut tmp).await.ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(clen);
    Some(body)
}

async fn write_json(stream: &mut TcpStream, body: &[u8]) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await
}

async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_allows_a_reasonable_burst_then_blocks() {
        let mut rate = RateLimit::default();
        for _ in 0..RATE_MAX_REQUESTS {
            assert!(rate.allow());
        }
        assert!(!rate.allow());
    }

    #[test]
    fn load_audit_tip_reads_last_hash() {
        let path = std::env::temp_dir().join(format!(
            "seance-audit-tip-test-{}.jsonl",
            rand::random::<u64>()
        ));
        std::fs::write(
            &path,
            "{\"hash\":\"first\"}\nnot-json\n{\"hash\":\"second\"}\n",
        )
        .unwrap();
        assert_eq!(load_audit_tip(&path), "second");
        let _ = std::fs::remove_file(path);
    }

    fn saved(name: &str, host: &str, group: Option<&str>) -> crate::settings::SavedHost {
        crate::settings::SavedHost {
            name: name.into(),
            host: host.into(),
            port: 5900,
            username: None,
            has_password: false,
            group: group.map(Into::into),
        }
    }

    #[test]
    fn find_saved_host_matches_name_or_address_and_rejects_ambiguity() {
        let hosts = vec![
            saved("gpdc01", "10.0.0.1", Some("ping")),
            saved("lab", "10.0.0.2", Some("A")),
            saved("lab", "10.0.0.3", Some("B")),
        ];
        assert_eq!(
            find_saved_host(&hosts, "GPDC01", None).unwrap().host,
            "10.0.0.1"
        );
        assert_eq!(
            find_saved_host(&hosts, "10.0.0.2", None).unwrap().name,
            "lab"
        );
        assert!(find_saved_host(&hosts, "lab", None).is_err());
        assert_eq!(
            find_saved_host(&hosts, "lab", Some("b")).unwrap().host,
            "10.0.0.3"
        );
        assert!(find_saved_host(&hosts, "nope", None).is_err());
    }

    #[test]
    fn retarget_tools_are_the_tab_moving_tools() {
        for t in RETARGET_TOOLS {
            assert!(is_tab_tool(t));
        }
        assert!(!RETARGET_TOOLS.contains(&"list_tabs"));
        assert!(!RETARGET_TOOLS.contains(&"list_saved_hosts"));
    }

    #[test]
    fn arg_str_defaults_to_empty() {
        let args = json!({ "name": "gpdc01", "n": 3 });
        assert_eq!(arg_str(&args, "name"), "gpdc01");
        assert_eq!(arg_str(&args, "n"), "");
        assert_eq!(arg_str(&args, "missing"), "");
    }

    #[test]
    fn sha256_is_hex_encoded() {
        assert_eq!(
            hex_sha256(b"seance"),
            "8c9771035e10619d9c2e084cc0f914772bfff45bd0b0a37c831f98bdf4a94839"
        );
    }
}
