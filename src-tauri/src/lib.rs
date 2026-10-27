mod agent;
mod frames;
mod rfb;
mod settings;

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use tauri::{Manager, State};
use tauri_plugin_clipboard_manager::ClipboardExt;

/// All live sessions, keyed by tab id, plus which tab is focused (`active`) and
/// which one the Agent Bridge drives (`pinned`).
#[derive(Default)]
struct AppState(Mutex<AppInner>);

#[derive(Default)]
struct AppInner {
    sessions: HashMap<u32, rfb::SessionHandle>,
    /// What each tab is connected to, so the Agent Bridge can describe tabs.
    tabs: HashMap<u32, TabMeta>,
    next_id: u32,
    /// The tab the operator is currently viewing (streams; others are paused).
    active: Option<u32>,
    /// The tab the Agent Bridge acts on. Set by the operator in the panel, or
    /// by the agent itself via `switch_tab` / `open_saved_host` (the operator's
    /// `active` view is never changed by the agent).
    pinned: Option<u32>,
}

struct TabMeta {
    host: String,
    port: u16,
    name: String,
}

impl AppState {
    fn get(&self, id: u32) -> Result<rfb::SessionHandle, String> {
        self.0
            .lock()
            .unwrap()
            .sessions
            .get(&id)
            .cloned()
            .ok_or_else(|| format!("session {id} not found"))
    }

    fn get_active(&self, id: u32) -> Result<rfb::SessionHandle, String> {
        let inner = self.0.lock().unwrap();
        if inner.active != Some(id) {
            return Err(format!("session {id} is not the active tab"));
        }
        inner
            .sessions
            .get(&id)
            .cloned()
            .ok_or_else(|| format!("session {id} not found"))
    }

    /// The Agent Bridge's target: the pinned tab if set, else the active tab.
    /// `background` is true when that tab is not the one being viewed — the
    /// operator isn't watching it live.
    fn agent_target(&self) -> Option<(u32, rfb::SessionHandle, bool)> {
        let inner = self.0.lock().unwrap();
        let id = inner.pinned.or(inner.active)?;
        let handle = inner.sessions.get(&id).cloned()?;
        let background = inner.active != Some(id);
        Some((id, handle, background))
    }

    /// Every open tab as the Agent Bridge reports it: no handles, no secrets.
    fn tab_list(&self) -> Vec<serde_json::Value> {
        let inner = self.0.lock().unwrap();
        let target = inner.pinned.or(inner.active);
        let mut ids: Vec<u32> = inner.sessions.keys().copied().collect();
        ids.sort();
        ids.into_iter()
            .filter_map(|id| {
                let m = inner.tabs.get(&id)?;
                Some(serde_json::json!({
                    "tab": id, "name": m.name, "host": m.host, "port": m.port,
                    "viewing": inner.active == Some(id),
                    "agent_target": target == Some(id),
                }))
            })
            .collect()
    }

    /// The open tab already connected to `host:port`, if any (hostnames
    /// compare case-insensitively; the oldest tab wins if there are several).
    fn find_tab(&self, host: &str, port: u16) -> Option<u32> {
        let inner = self.0.lock().unwrap();
        inner
            .tabs
            .iter()
            .filter(|(id, m)| {
                m.host.eq_ignore_ascii_case(host)
                    && m.port == port
                    && inner.sessions.contains_key(id)
            })
            .map(|(id, _)| *id)
            .min()
    }

    fn has_tab(&self, id: u32) -> bool {
        self.0.lock().unwrap().sessions.contains_key(&id)
    }

    /// Whether `id` is open but not the tab the operator is viewing.
    fn is_background(&self, id: u32) -> bool {
        self.0.lock().unwrap().active != Some(id)
    }

    /// Set the Agent Bridge's target tab (the operator's view is untouched).
    fn pin(&self, id: u32) -> Result<(), String> {
        let mut inner = self.0.lock().unwrap();
        if !inner.sessions.contains_key(&id) {
            return Err(format!("tab {id} not found"));
        }
        inner.pinned = Some(id);
        Ok(())
    }

    /// A tab streams (keeps requesting updates) if it's the focused tab OR the
    /// pinned tab — so the agent always has a fresh framebuffer of its target,
    /// even when the operator is viewing a different tab. Every other tab is
    /// paused (zero bandwidth). Returns the handles that just transitioned from
    /// paused to streaming, so the caller can kick a full frame for them.
    fn resync_streaming(&self) -> Vec<rfb::SessionHandle> {
        let inner = self.0.lock().unwrap();
        let mut kick = Vec::new();
        for (id, h) in inner.sessions.iter() {
            let want = Some(*id) == inner.active || Some(*id) == inner.pinned;
            let was = h.is_active();
            h.set_active(want);
            if want && !was {
                kick.push(h.clone());
            }
        }
        kick
    }
}

/// Repaint any tabs that just started streaming.
async fn kick_streaming(state: &AppState) {
    for h in state.resync_streaming() {
        let _ = h.request_update(false).await;
    }
}

// --- session lifecycle ------------------------------------------------------

/// Who opened a session. The operator's new tab takes focus; the Agent
/// Bridge's becomes its pinned target and leaves the operator's view alone
/// (it only takes focus when nothing else is open).
#[derive(Clone, Copy)]
enum Opener {
    Operator,
    Agent,
}

/// Open a session in a new tab.
#[allow(clippy::too_many_arguments)]
async fn open_session(
    app: tauri::AppHandle,
    state: &AppState,
    channel: &frames::FrameChannel,
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    opener: Opener,
) -> Result<serde_json::Value, String> {
    let id = {
        let mut inner = state.0.lock().unwrap();
        inner.next_id += 1;
        inner.next_id
    };
    let frames = channel.clone();
    let (handle, info) = rfb::connect(app, frames, id, host.clone(), port, username, password)
        .await
        .map_err(|e| e.to_string())?;
    {
        let mut inner = state.0.lock().unwrap();
        inner.sessions.insert(id, handle);
        inner.tabs.insert(
            id,
            TabMeta {
                host,
                port,
                name: info.name.clone(),
            },
        );
        match opener {
            Opener::Operator => inner.active = Some(id),
            Opener::Agent => {
                inner.pinned = Some(id);
                if inner.active.is_none() {
                    inner.active = Some(id);
                }
            }
        }
    }
    // the new tab (and any pinned tab) streams; everything else pauses
    kick_streaming(state).await;
    Ok(serde_json::json!({ "id": id, "info": info }))
}

/// Open a session with the password the OS credential store holds for
/// `host:port`, if any. The secret goes straight into the RFB handshake —
/// never to renderer JavaScript or an Agent Bridge caller.
async fn open_stored_session(
    app: tauri::AppHandle,
    state: &AppState,
    channel: &frames::FrameChannel,
    host: String,
    port: u16,
    username: Option<String>,
    opener: Opener,
) -> Result<serde_json::Value, String> {
    let password = host_secret_entry(&host, port).and_then(|e| e.get_password().ok());
    open_session(app, state, channel, host, port, username, password, opener).await
}

/// Open a new session in its own tab. Returns `{ id, info }`.
#[tauri::command]
async fn connect(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    channel: State<'_, frames::FrameChannel>,
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
) -> Result<serde_json::Value, String> {
    open_session(
        app,
        state.inner(),
        channel.inner(),
        host,
        port,
        username,
        password,
        Opener::Operator,
    )
    .await
}

/// Open a session using a password held in the OS credential store, without
/// returning that secret to renderer JavaScript.
#[tauri::command]
async fn connect_stored(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    channel: State<'_, frames::FrameChannel>,
    host: String,
    port: u16,
    username: Option<String>,
) -> Result<serde_json::Value, String> {
    open_stored_session(
        app,
        state.inner(),
        channel.inner(),
        host,
        port,
        username,
        Opener::Operator,
    )
    .await
}

/// Close one tab's session.
#[tauri::command]
async fn disconnect(state: State<'_, AppState>, id: u32) -> Result<(), String> {
    let removed = {
        let mut inner = state.0.lock().unwrap();
        let removed = inner.sessions.remove(&id);
        inner.tabs.remove(&id);
        if inner.pinned == Some(id) {
            inner.pinned = None;
        }
        if inner.active == Some(id) {
            // The webview decides which tab to show next and calls set_active.
            // Guessing here could leave the backend believing the operator
            // views a different tab than the one on screen.
            inner.active = None;
        }
        removed
    };
    if let Some(h) = removed {
        h.shutdown().await;
    }
    // any pinned tab keeps streaming; the next focused tab resumes via set_active
    kick_streaming(&state).await;
    Ok(())
}

/// Switch the focused tab: pause the others (except a pinned tab), resume this
/// one with a full frame.
#[tauri::command]
async fn set_active(state: State<'_, AppState>, id: u32) -> Result<(), String> {
    {
        let mut inner = state.0.lock().unwrap();
        if !inner.sessions.contains_key(&id) {
            return Err(format!("session {id} not found"));
        }
        inner.active = Some(id);
    }
    kick_streaming(&state).await;
    Ok(())
}

/// Pin (or unpin, with `null`) the tab the Agent Bridge drives. A pinned tab
/// keeps streaming even when the operator views another tab, so the agent's
/// screenshots stay current.
#[tauri::command]
async fn set_pinned(
    state: State<'_, AppState>,
    bridge: State<'_, agent::AgentBridge>,
    id: Option<u32>,
) -> Result<(), String> {
    let changed = {
        let mut inner = state.0.lock().unwrap();
        let next = match id {
            Some(i) if inner.sessions.contains_key(&i) => Some(i),
            _ => None,
        };
        std::mem::replace(&mut inner.pinned, next) != next
    };
    // an acknowledgement given for one background tab never carries over
    if changed {
        bridge.clear_background_ack();
    }
    kick_streaming(&state).await;
    Ok(())
}

// --- per-session input ------------------------------------------------------

#[tauri::command]
async fn send_pointer(
    state: State<'_, AppState>,
    session_id: u32,
    x: u16,
    y: u16,
    buttons: u8,
) -> Result<(), String> {
    state
        .get_active(session_id)?
        .send_pointer(x, y, buttons)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn send_key(
    state: State<'_, AppState>,
    session_id: u32,
    keysym: u32,
    down: bool,
) -> Result<(), String> {
    state
        .get_active(session_id)?
        .send_key(keysym, down)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn type_text(
    state: State<'_, AppState>,
    session_id: u32,
    text: String,
) -> Result<(), String> {
    state
        .get_active(session_id)?
        .type_text(&text)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn type_clipboard(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    session_id: u32,
) -> Result<usize, String> {
    let text = app.clipboard().read_text().map_err(|e| e.to_string())?;
    if text.is_empty() {
        return Ok(0);
    }
    let count = text.chars().count();
    state
        .get_active(session_id)?
        .type_text(&text)
        .await
        .map_err(|e| e.to_string())?;
    Ok(count)
}

fn copy_to_clipboard(app: &tauri::AppHandle, text: String) -> Result<(), String> {
    app.clipboard().write_text(text).map_err(|e| e.to_string())
}

#[tauri::command]
async fn request_update(
    state: State<'_, AppState>,
    session_id: u32,
    incremental: bool,
) -> Result<(), String> {
    state
        .get(session_id)?
        .request_update(incremental)
        .await
        .map_err(|e| e.to_string())
}

// --- frame channel + agent bridge ------------------------------------------

/// Where the webview should connect for binary framebuffer traffic.
#[tauri::command]
fn frame_endpoint(channel: State<'_, frames::FrameChannel>) -> String {
    channel.endpoint()
}

/// MCP endpoint plus the current consent policy so the panel opens showing
/// reality. The bearer token is never returned to renderer JavaScript.
#[tauri::command]
fn agent_bridge_info(bridge: State<'_, agent::AgentBridge>) -> serde_json::Value {
    let (mode, allow) = bridge.consent_strings();
    serde_json::json!({
        "endpoint": bridge.endpoint(),
        "mode": mode,
        "allow": allow,
        "all_tabs": bridge.background_autonomy(),
    })
}

#[tauri::command]
fn agent_copy_endpoint(
    app: tauri::AppHandle,
    bridge: State<'_, agent::AgentBridge>,
) -> Result<(), String> {
    copy_to_clipboard(&app, bridge.endpoint())
}

#[tauri::command]
fn agent_copy_bridge_token(
    app: tauri::AppHandle,
    bridge: State<'_, agent::AgentBridge>,
) -> Result<(), String> {
    copy_to_clipboard(&app, bridge.token())?;
    bridge.audit_note("operator copied the MCP bearer token");
    Ok(())
}

#[tauri::command]
fn agent_copy_add_command(
    app: tauri::AppHandle,
    bridge: State<'_, agent::AgentBridge>,
) -> Result<(), String> {
    let cmd = format!(
        "claude mcp add --transport http seance {} --header \"Authorization: Bearer {}\"",
        bridge.endpoint(),
        bridge.token()
    );
    copy_to_clipboard(&app, cmd)?;
    bridge.audit_note("operator copied the MCP registration command");
    Ok(())
}

// --- saved hosts (connection manager) ---------------------------------------
//
// Metadata lives in settings.json; passwords live only in the OS credential
// store under service "seance-hosts", keyed by "host:port". The webview asks
// for a secret just-in-time when connecting and never stores it.

const HOSTS_KEYRING: &str = "seance-hosts";

fn host_secret_entry(host: &str, port: u16) -> Option<keyring::Entry> {
    keyring::Entry::new(HOSTS_KEYRING, &format!("{host}:{port}")).ok()
}

#[tauri::command]
fn hosts_list(app: tauri::AppHandle) -> Vec<settings::SavedHost> {
    settings::load(&app).hosts
}

/// Upsert a saved host after a successful connect (matched by host+port).
/// User-owned metadata is preserved on existing entries: `name` sticks once
/// set (renames go through `hosts_update_meta`), `group` only changes when
/// the caller supplies one, and `username` is never blanked by a
/// passwordless reconnect. `password` semantics: `None` leaves any stored
/// secret untouched; `Some("")` deletes it; `Some(p)` stores it. Returns the
/// updated list.
#[tauri::command]
fn hosts_save(
    app: tauri::AppHandle,
    mut entry: settings::SavedHost,
    password: Option<String>,
) -> Vec<settings::SavedHost> {
    let mut s = settings::load(&app);
    let existing = s
        .hosts
        .iter()
        .position(|h| h.host == entry.host && h.port == entry.port);
    if let Some(i) = existing {
        let old = &s.hosts[i];
        entry.name = old.name.clone();
        entry.has_password = old.has_password;
        if entry.group.is_none() {
            entry.group = old.group.clone();
        }
        if entry.username.is_none() {
            entry.username = old.username.clone();
        }
    }
    match password.as_deref() {
        Some("") => {
            if let Some(e) = host_secret_entry(&entry.host, entry.port) {
                let _ = e.delete_credential();
            }
            entry.has_password = false;
        }
        Some(p) => {
            if let Some(e) = host_secret_entry(&entry.host, entry.port) {
                entry.has_password = e.set_password(p).is_ok();
            }
        }
        None => {}
    }
    match existing {
        Some(i) => s.hosts[i] = entry,
        None => s.hosts.push(entry),
    }
    settings::save(&app, &s);
    s.hosts
}

/// Explicit metadata edit from the UI: rename and/or re-file a saved host.
/// An empty `group` un-files it; an empty `name` is ignored.
#[tauri::command]
fn hosts_update_meta(
    app: tauri::AppHandle,
    host: String,
    port: u16,
    name: String,
    group: Option<String>,
) -> Vec<settings::SavedHost> {
    let mut s = settings::load(&app);
    if let Some(h) = s
        .hosts
        .iter_mut()
        .find(|h| h.host == host && h.port == port)
    {
        if !name.trim().is_empty() {
            h.name = name.trim().to_string();
        }
        h.group = group
            .map(|g| g.trim().to_string())
            .filter(|g| !g.is_empty());
    }
    settings::save(&app, &s);
    s.hosts
}

#[tauri::command]
fn hosts_delete(app: tauri::AppHandle, host: String, port: u16) -> Vec<settings::SavedHost> {
    let mut s = settings::load(&app);
    s.hosts.retain(|h| !(h.host == host && h.port == port));
    if let Some(e) = host_secret_entry(&host, port) {
        let _ = e.delete_credential();
    }
    settings::save(&app, &s);
    s.hosts
}

/// Mint and persist a new MCP bearer token; the old one stops working
/// immediately.
#[tauri::command]
fn agent_rotate_token(bridge: State<'_, agent::AgentBridge>) {
    bridge.rotate_token();
}

/// Set the consent policy: "ask" | "autonomous" | an allow-list of tool names.
/// Persisted, so the operator's chosen posture survives restarts.
#[tauri::command]
fn agent_set_consent(
    app: tauri::AppHandle,
    bridge: State<'_, agent::AgentBridge>,
    mode: String,
    allow: Option<Vec<String>>,
) {
    let allow_list = allow.unwrap_or_default();
    let consent = match mode.as_str() {
        "autonomous" => agent::ConsentMode::Autonomous,
        "allowlist" => {
            agent::ConsentMode::AllowList(allow_list.iter().cloned().collect::<HashSet<_>>())
        }
        _ => agent::ConsentMode::Ask,
    };
    bridge.set_consent(consent);
    let mut s = settings::load(&app);
    s.consent_mode = Some(mode);
    s.allow_list = allow_list;
    settings::save(&app, &s);
}

/// The operator's answer to a pending consent prompt.
#[tauri::command]
fn agent_consent_respond(bridge: State<'_, agent::AgentBridge>, id: u64, approved: bool) {
    bridge.resolve_consent(id, approved);
}

/// Record, in the audit log, that the operator accepted responsibility for the
/// agent acting autonomously on a tab they aren't watching (pinned background
/// tab + autonomous consent). The UI calls this when the operator dismisses the
/// warning banner.
#[tauri::command]
fn agent_accept_background(bridge: State<'_, agent::AgentBridge>) {
    bridge.accept_background();
}

/// Operator setting: auto-approved agent calls also run on tabs they aren't
/// viewing. Deliberately not persisted — re-armed each launch, like autonomous.
#[tauri::command]
fn agent_set_background_autonomy(bridge: State<'_, agent::AgentBridge>, enabled: bool) {
    bridge.set_background_autonomy(enabled);
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(AppState::default())
        .setup(|app| {
            let channel = tauri::async_runtime::block_on(frames::FrameChannel::start())
                .map_err(|e| e as Box<dyn std::error::Error>)?;
            app.manage(channel);
            let bridge =
                tauri::async_runtime::block_on(agent::AgentBridge::start(app.handle().clone()))
                    .map_err(|e| e as Box<dyn std::error::Error>)?;
            // Restore the operator's persisted consent posture — but never
            // silently come back up in "autonomous". A blanket auto-approve is
            // too dangerous to inherit across launches unattended; it must be
            // re-armed deliberately each session. Allow-list and ask persist.
            let saved = settings::load(app.handle());
            if let Some(mode) = saved.consent_mode.as_deref() {
                bridge.set_consent(match mode {
                    "allowlist" => {
                        agent::ConsentMode::AllowList(saved.allow_list.iter().cloned().collect())
                    }
                    _ => agent::ConsentMode::Ask,
                });
            }
            app.manage(bridge);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            frame_endpoint,
            agent_bridge_info,
            agent_copy_endpoint,
            agent_copy_bridge_token,
            agent_copy_add_command,
            agent_rotate_token,
            hosts_list,
            hosts_save,
            hosts_update_meta,
            hosts_delete,
            agent_set_consent,
            agent_consent_respond,
            agent_accept_background,
            agent_set_background_autonomy,
            connect,
            connect_stored,
            disconnect,
            set_active,
            set_pinned,
            send_pointer,
            send_key,
            type_text,
            type_clipboard,
            request_update
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
