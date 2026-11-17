//! Agent Bridge (agentless).
//!
//! Exposes a local MCP *server* so any MCP-speaking assistant (Claude Code,
//! Claude Desktop, Codex, …) can observe and drive the user's authenticated
//! sessions. It is built entirely on primitives the client
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
//!   - **Session scoping.** Tools reach only tabs the operator shared with
//!     agents, or the tab being viewed when none is shared. With several
//!     shared, every call must name its `target`; an agent can never address
//!     a host the user isn't connected to.

mod keys;
mod target;

pub use target::{label as tab_label, resolve as resolve_target, TabInfo};

use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
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
/// acknowledgement stays valid before it must be re-armed. Acks live in
/// memory only, so a restart always asks again.
const BG_ACK_TTL: Duration = Duration::from_secs(24 * 60 * 60);

const MAX_MCP_SESSIONS: usize = 32;
const MAX_AGENT_NAME: usize = 64;

/// Client names keyed by the `Mcp-Session-Id` minted at `initialize`, so two
/// agents on one bridge get distinct labels. Oldest entries are evicted.
#[derive(Default)]
struct McpSessions {
    order: VecDeque<String>,
    names: HashMap<String, String>,
}

impl McpSessions {
    fn insert(&mut self, id: String, name: String) {
        if self.order.len() >= MAX_MCP_SESSIONS {
            if let Some(old) = self.order.pop_front() {
                self.names.remove(&old);
            }
        }
        self.order.push_back(id.clone());
        self.names.insert(id, name);
    }

    /// The agent label for a request's `Mcp-Session-Id`. An id this bridge
    /// didn't issue (one minted before a restart, say) is still distinct per
    /// client, so it keeps its prefix rather than borrowing another client's name.
    fn label(&self, id: Option<&str>) -> String {
        match id {
            Some(id) if id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()) => {
                let name = self.names.get(id).map_or("unknown agent", String::as_str);
                format!("{name} #{}", &id[..4])
            }
            _ => "unknown agent".into(),
        }
    }
}

struct Inner {
    endpoint: String,
    token: Mutex<String>,
    app: AppHandle,
    consent: Mutex<ConsentMode>,
    pending: Mutex<HashMap<u64, oneshot::Sender<bool>>>,
    next_id: AtomicU64,
    mcp_sessions: Mutex<McpSessions>,
    audit_path: PathBuf,
    audit_tip: Mutex<String>,
    rate: Mutex<RateLimit>,
    /// Per tab, the expiry of the operator's acknowledgement for autonomous
    /// actions while that tab is in the background. Enforced in `decide`, not
    /// just the UI.
    bg_ack_until: Mutex<HashMap<u32, std::time::Instant>>,
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
            mcp_sessions: Mutex::new(McpSessions::default()),
            audit_path,
            audit_tip: Mutex::new(audit_tip),
            rate: Mutex::new(RateLimit::default()),
            bg_ack_until: Mutex::new(HashMap::new()),
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

    /// The operator accepts responsibility for autonomous actions on one tab
    /// while they aren't watching it. Arms a time-limited, backend-held
    /// acknowledgement that `decide` requires; the UI banner is a prompt, this
    /// is the enforcement. Returns the expiry in epoch ms for the panel.
    pub fn accept_background(&self, tab: u32, name: &str) -> u64 {
        self.0
            .bg_ack_until
            .lock()
            .unwrap()
            .insert(tab, std::time::Instant::now() + BG_ACK_TTL);
        self.audit_note(&format!(
            "operator accepted responsibility: autonomous agent actions on background tab {name} ({}h)",
            BG_ACK_TTL.as_secs() / 3600
        ));
        now_ms() + BG_ACK_TTL.as_millis() as u64
    }

    /// Unexpired acknowledgements as `(tab, expiry in epoch ms)`, so a
    /// remounted panel shows the backend's truth.
    pub fn background_acks(&self) -> Vec<(u32, u64)> {
        let now = std::time::Instant::now();
        let wall = now_ms();
        self.0
            .bg_ack_until
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, t)| **t > now)
            .map(|(tab, t)| (*tab, wall + (*t - now).as_millis() as u64))
            .collect()
    }

    /// Drop a tab's background acknowledgement when it stops being shared or
    /// closes, so a later tab can't inherit it.
    pub fn clear_background(&self, tab: u32) {
        self.0.bg_ack_until.lock().unwrap().remove(&tab);
    }

    fn bg_ack_valid(&self, tab: u32) -> bool {
        matches!(self.0.bg_ack_until.lock().unwrap().get(&tab), Some(t) if *t > std::time::Instant::now())
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
                None,
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

        let mut new_session = None;
        let envelope = match rpc_method {
            "initialize" => {
                let name: String = params
                    .get("clientInfo")
                    .and_then(|c| c.get("name"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("unknown agent")
                    .chars()
                    .take(MAX_AGENT_NAME)
                    .collect();
                let sid = format!("{:032x}", rand::random::<u128>());
                self.0.mcp_sessions.lock().unwrap().insert(sid.clone(), name);
                new_session = Some(sid);
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
            "tools/call" => {
                let agent = self
                    .0
                    .mcp_sessions
                    .lock()
                    .unwrap()
                    .label(headers.get("mcp-session-id").map(String::as_str));
                ok_envelope(&id, self.call_tool(&params, &agent).await)
            }
            other => err_envelope(&id, -32601, &format!("method not found: {other}")),
        };

        write_json(&mut stream, &envelope, new_session.as_deref()).await
    }

    // --- Tool dispatch -------------------------------------------------------

    async fn call_tool(&self, params: &Value, agent: &str) -> Value {
        let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
        let args = params.get("arguments").cloned().unwrap_or(json!({}));
        let saved = crate::settings::load(&self.0.app).hosts;
        let state = self.0.app.state::<crate::AppState>();

        // list_targets reads tab metadata only, so it has no tab of its own.
        let target = if name == "list_targets" {
            None
        } else {
            match target_arg(&args).and_then(|t| state.agent_target(t.as_deref(), &saved)) {
                Ok(t) => Some(t),
                Err(e) => {
                    self.audit(agent, name, &args, None, false, "refused", &e);
                    let _ = self.0.app.emit(
                        "agent-activity",
                        json!({ "phase": "error", "agent": agent, "tool": name, "error": e,
                                "ts": now_ms() }),
                    );
                    return tool_error(&e);
                }
            }
        };
        let tab = target.as_ref().map(|t| t.0);
        let background = target.as_ref().is_some_and(|t| t.2);

        let _ = self.0.app.emit(
            "agent-activity",
            json!({ "phase": "requested", "agent": agent, "tool": name, "args": args,
                    "tab": tab, "background": background, "ts": now_ms() }),
        );

        let Some(approved_by) = self.decide(agent, name, tab, background).await else {
            self.audit(agent, name, &args, tab, background, "denied", "");
            let _ = self.0.app.emit(
                "agent-activity",
                json!({ "phase": "denied", "agent": agent, "tool": name, "tab": tab,
                        "ts": now_ms() }),
            );
            return tool_error("denied by operator");
        };

        let result = match &target {
            Some((tab, session, _)) => {
                let on = format!(
                    "{} (tab {tab})",
                    tab_label(session.host(), session.port(), &saved)
                );
                self.execute(name, &args, session, &on).await
            }
            None => Ok(list_targets(&state.agent_tabs(), &saved)),
        };

        match result {
            Ok(v) => {
                self.audit(agent, name, &args, tab, background, approved_by, "ok");
                let _ = self.0.app.emit(
                    "agent-activity",
                    json!({ "phase": "completed", "agent": agent, "tool": name, "tab": tab,
                            "background": background, "ts": now_ms() }),
                );
                v
            }
            Err(e) => {
                self.audit(
                    agent,
                    name,
                    &args,
                    tab,
                    background,
                    approved_by,
                    &format!("error: {e}"),
                );
                let _ = self.0.app.emit(
                    "agent-activity",
                    json!({ "phase": "error", "agent": agent, "tool": name, "tab": tab,
                            "error": e, "ts": now_ms() }),
                );
                tool_error(&e)
            }
        }
    }

    /// The audit decision for an approved call (`approved by policy` or
    /// `approved by operator`), or `None` when the operator denied it.
    async fn decide(
        &self,
        agent: &str,
        tool: &str,
        tab: Option<u32>,
        background: bool,
    ) -> Option<&'static str> {
        let auto = match &*self.0.consent.lock().unwrap() {
            ConsentMode::Autonomous => true,
            ConsentMode::AllowList(set) => set.contains(tool),
            ConsentMode::Ask => false,
        };
        // Never auto-approve an action on a tab the operator isn't watching
        // without a live, backend-held acknowledgement for that tab, even in
        // autonomous or allow-list mode. Otherwise fall through to a prompt.
        if auto && !(background && !tab.is_some_and(|t| self.bg_ack_valid(t))) {
            return Some("approved by policy");
        }
        self.ask(agent, tool, tab)
            .await
            .then_some("approved by operator")
    }

    async fn ask(&self, agent: &str, tool: &str, tab: Option<u32>) -> bool {
        let id = self.0.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        self.0.pending.lock().unwrap().insert(id, tx);
        let _ = self.0.app.emit(
            "agent-consent-request",
            json!({ "id": id, "tool": tool, "tab": tab, "agent": agent, "ts": now_ms() }),
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
        on: &str,
    ) -> Result<Value, String> {
        let (fbw, fbh) = session.dims();
        let clamp_x = |v: i64| v.clamp(0, fbw.saturating_sub(1) as i64) as u16;
        let clamp_y = |v: i64| v.clamp(0, fbh.saturating_sub(1) as i64) as u16;
        let arg_i = |k: &str| args.get(k).and_then(|v| v.as_i64());
        let arg_s = |k: &str| args.get(k).and_then(|v| v.as_str()).unwrap_or("");

        match name {
            "screenshot" => {
                let png = session.screenshot_png().map_err(|e| e.to_string())?;
                let b64 = base64::engine::general_purpose::STANDARD.encode(&png);
                Ok(json!({
                    "content": [
                        { "type": "image", "data": b64, "mimeType": "image/png" },
                        { "type": "text", "text": format!("screen of {on}") }
                    ]
                }))
            }
            "type_text" => {
                let text = arg_s("text");
                session.type_text(text).await.map_err(|e| e.to_string())?;
                Ok(tool_ok(&format!(
                    "typed {} characters on {on}",
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
                Ok(tool_ok(&format!("key combo sent to {on}")))
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
                Ok(tool_ok(&format!("pointer at {x},{y} on {on}")))
            }
            "click" => {
                let (x, y) = (
                    clamp_x(arg_i("x").unwrap_or(0)),
                    clamp_y(arg_i("y").unwrap_or(0)),
                );
                let mask = match arg_s("button") {
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
                Ok(tool_ok(&format!("clicked {x},{y} on {on}")))
            }
            "scroll" => {
                let (x, y) = (
                    clamp_x(arg_i("x").unwrap_or(0)),
                    clamp_y(arg_i("y").unwrap_or(0)),
                );
                let bit = if arg_s("direction") == "up" {
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
                Ok(tool_ok(&format!("scrolled {} on {on}", arg_s("direction"))))
            }
            "get_clipboard" => Ok(json!({
                "content": [
                    { "type": "text", "text": session.remote_clipboard() },
                    { "type": "text", "text": format!("clipboard of {on}") }
                ]
            })),
            "set_clipboard" => {
                let text = arg_s("text");
                session
                    .set_remote_clipboard(text)
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(tool_ok(&format!("remote clipboard set on {on}")))
            }
            other => Err(format!("unknown tool: {other}")),
        }
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
    ) {
        self.append_audit(json!({
            "ts": now_ms(), "agent": agent, "tool": tool, "args": redact_args(tool, args),
            "tab": tab, "background": background, "decision": decision, "result": result
        }));
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
    let mut tools = json!([
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
            "description": "Press a chord, e.g. [\"ctrl\",\"alt\",\"delete\"] or [\"ctrl\",\"c\"]. Keys are pressed in order and released in reverse. To paste in Windows Terminal, use [\"ctrl\",\"shift\",\"v\"]: the terminal handles it itself, while [\"ctrl\",\"v\"] goes to the shell. If a terminal prompt shows a literal ^V or ^H, a killed program left that console in raw input mode and more typing will not fix it; open a new terminal tab with [\"ctrl\",\"shift\",\"t\"].",
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
            "description": "Set the remote clipboard via the standard VNC clipboard channel. Then paste with the app's own chord: [\"ctrl\",\"shift\",\"v\"] in Windows Terminal, [\"ctrl\",\"v\"] in most other Windows apps.",
            "inputSchema": {
                "type": "object",
                "properties": { "text": { "type": "string" } },
                "required": ["text"]
            }
        }
    ]);
    if let Some(list) = tools.as_array_mut() {
        for tool in list.iter_mut() {
            tool["inputSchema"]["properties"]["target"] = json!({
                "type": "string",
                "description": "Which session to act on: a saved host name, host[:port], or a tab id from list_targets. Required when the operator has shared more than one session."
            });
        }
        list.push(json!({
            "name": "list_targets",
            "description": "List the sessions the operator has shared with agents: tab id, name, address, and whether the operator is viewing it. Pass one as `target` to the other tools.",
            "inputSchema": { "type": "object", "properties": {} }
        }));
    }
    tools
}

fn list_targets(tabs: &[TabInfo], saved: &[crate::settings::SavedHost]) -> Value {
    let list: Vec<Value> = target::addressable(tabs)
        .iter()
        .map(|t| {
            json!({
                "tab": t.id,
                "name": tab_label(&t.host, t.port, saved),
                "address": format!("{}:{}", t.host, t.port),
                "viewing": t.active,
                "shared": t.pinned,
            })
        })
        .collect();
    tool_ok(&serde_json::to_string_pretty(&list).unwrap_or_default())
}

/// The call's `target`. Agents may send a tab id as a JSON number.
fn target_arg(args: &Value) -> Result<Option<String>, String> {
    match args.get("target") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(Value::Number(n)) => Ok(Some(n.to_string())),
        Some(_) => Err("`target` must be a string".into()),
    }
}

// --- small helpers ----------------------------------------------------------

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

async fn write_json(
    stream: &mut TcpStream,
    body: &[u8],
    session_id: Option<&str>,
) -> std::io::Result<()> {
    let session = session_id
        .map(|s| format!("Mcp-Session-Id: {s}\r\n"))
        .unwrap_or_default();
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{session}Connection: close\r\n\r\n",
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

    #[test]
    fn mcp_sessions_label_known_ids_and_evict_the_oldest() {
        let mut s = McpSessions::default();
        let id = |n: usize| format!("{n:032x}");
        for n in 0..MAX_MCP_SESSIONS {
            s.insert(id(n), format!("agent{n}"));
        }
        assert_eq!(s.label(Some(&id(0))), "agent0 #0000");
        s.insert(id(MAX_MCP_SESSIONS), "late".into());
        assert_eq!(s.label(Some(&id(0))), "unknown agent #0000");
        assert_eq!(s.label(Some(&id(MAX_MCP_SESSIONS))), "late #0000");
        assert_eq!(s.names.len(), MAX_MCP_SESSIONS);
    }

    #[test]
    fn unknown_sessions_never_borrow_another_clients_name() {
        let mut s = McpSessions::default();
        s.insert("a".repeat(32), "claude-code".into());
        assert_eq!(s.label(Some(&"dead".repeat(8))), "unknown agent #dead");
        assert_eq!(s.label(Some("not-a-session")), "unknown agent");
        assert_eq!(s.label(None), "unknown agent");
    }

    #[test]
    fn target_arg_accepts_strings_and_tab_numbers() {
        assert_eq!(target_arg(&json!({})), Ok(None));
        assert_eq!(target_arg(&json!({ "target": "AGENT01" })), Ok(Some("AGENT01".into())));
        assert_eq!(target_arg(&json!({ "target": 3 })), Ok(Some("3".into())));
        assert!(target_arg(&json!({ "target": ["AGENT01"] })).is_err());
    }

    #[test]
    fn every_tool_takes_a_target_except_list_targets() {
        let specs = tool_specs();
        for t in specs.as_array().unwrap() {
            let has = t["inputSchema"]["properties"].get("target").is_some();
            assert_eq!(has, t["name"] != "list_targets", "{}", t["name"]);
        }
    }

    #[test]
    fn sha256_is_hex_encoded() {
        assert_eq!(
            hex_sha256(b"seance"),
            "8c9771035e10619d9c2e084cc0f914772bfff45bd0b0a37c831f98bdf4a94839"
        );
    }
}
