//! Minimal RFB (VNC) client core, owned end-to-end so input features like
//! clipboard-to-keystrokes work everywhere — including remote login screens
//! where ClientCutText clipboard sync is useless.
//!
//! Scope: RFB 3.8, security types None(1), VncAuth(2) and Apple DH(30, the
//! native macOS Screen Sharing auth); Raw, ZRLE and CopyRect encodings plus
//! Cursor and DesktopSize pseudo-encodings. Decoded
//! RGBA draw operations ship to the webview over the binary loopback
//! WebSocket (`frames::FrameChannel`); only low-rate lifecycle events
//! (disconnect, clipboard, bell) use Tauri's JSON event IPC.

mod apple_auth;
mod des_auth;
mod framebuffer;
mod keysym;
mod zrle;

use crate::frames::FrameChannel;
use framebuffer::Framebuffer;
pub use keysym::char_to_keysym;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::{AppHandle, Emitter};
use tauri_plugin_clipboard_manager::ClipboardExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::{sleep, timeout, Duration};

pub type Error = Box<dyn std::error::Error + Send + Sync>;

// --- resource limits --------------------------------------------------------
//
// A hostile or buggy VNC server must never be able to make us allocate
// unbounded memory. Every server-controlled size is bounded before it drives an
// allocation. The ceilings are generous for legitimate desktops (8K, wide
// multi-monitor spans) but reject the absurd.

/// Max framebuffer side, in pixels. Covers ultra-wide multi-monitor spans.
const MAX_DIM: u16 = 16384;
/// Max total framebuffer area (~256 MB at RGBA). Bounds every in-bounds rect too.
const MAX_FB_PIXELS: usize = 64 << 20;
/// Cursors are small glyphs; anything past this is nonsense.
const MAX_CURSOR_DIM: u16 = 1024;
/// Cap on a single ServerCutText clipboard payload.
const MAX_CLIPBOARD: usize = 4 << 20;
/// Cap on the compressed size of one ZRLE rect before we inflate it.
const MAX_ZRLE_COMPRESSED: usize = 64 << 20;

/// Reject framebuffer dimensions that exceed our allocation ceilings.
fn check_dims(width: u16, height: u16) -> Result<(), Error> {
    if width == 0
        || height == 0
        || width > MAX_DIM
        || height > MAX_DIM
        || (width as usize) * (height as usize) > MAX_FB_PIXELS
    {
        return Err(format!("server framebuffer {width}x{height} exceeds limits").into());
    }
    Ok(())
}

/// Reject a rect that falls outside the negotiated framebuffer — this bounds
/// every raw/ZRLE allocation to the (already bounded) framebuffer area, so a
/// server can't claim a 65535×65535 rect and make us allocate ~17 GB.
fn check_rect(fbw: u16, fbh: u16, x: u16, y: u16, w: u16, h: u16) -> Result<(), Error> {
    if x as u32 + w as u32 > fbw as u32 || y as u32 + h as u32 > fbh as u32 {
        return Err(
            format!("rect {w}x{h}@{x},{y} falls outside the {fbw}x{fbh} framebuffer").into(),
        );
    }
    Ok(())
}

#[derive(Serialize, Clone)]
pub struct ServerInfo {
    pub width: u16,
    pub height: u16,
    pub name: String,
    /// Which auth actually happened: "none" (unauthenticated), "vnc-auth"
    /// (legacy DES, ≤8-char-effective), or "apple-dh" (anonymous DH, no server
    /// identity). Surfaced so the UI can be honest about the session's posture.
    pub security: String,
    /// Whether the transport is encrypted. Always false today — raw TCP;
    /// TLS/VeNCrypt support is on the roadmap.
    pub encrypted: bool,
}

struct Inner {
    writer: Mutex<OwnedWriteHalf>,
    closed: AtomicBool,
    fb: std::sync::Mutex<Framebuffer>,
    /// Last text the server sent via ServerCutText — the remote clipboard, as
    /// last observed. Exposed to the Agent Bridge's `get_clipboard`.
    remote_clipboard: std::sync::Mutex<String>,
    /// This session's tab id — tags every draw op so the webview routes it to
    /// the right canvas, and identifies the tab in the disconnect event.
    session_id: u32,
    /// The address the operator connected to. The Agent Bridge matches a
    /// tool call's `target` against it.
    host: String,
    port: u16,
    /// Whether this tab is currently visible. Hidden tabs stop requesting
    /// incremental updates, so a backgrounded session uses zero bandwidth until
    /// it's shown again.
    active: AtomicBool,
}

#[derive(Clone)]
pub struct SessionHandle(Arc<Inner>);

impl SessionHandle {
    pub async fn send_pointer(&self, x: u16, y: u16, buttons: u8) -> Result<(), Error> {
        let mut msg = [5u8, buttons, 0, 0, 0, 0];
        msg[2..4].copy_from_slice(&x.to_be_bytes());
        msg[4..6].copy_from_slice(&y.to_be_bytes());
        self.0.writer.lock().await.write_all(&msg).await?;
        Ok(())
    }

    pub async fn send_key(&self, keysym: u32, down: bool) -> Result<(), Error> {
        let mut msg = [4u8, down as u8, 0, 0, 0, 0, 0, 0];
        msg[4..8].copy_from_slice(&keysym.to_be_bytes());
        self.0.writer.lock().await.write_all(&msg).await?;
        Ok(())
    }

    /// The headline feature: type arbitrary text as synthesized keystrokes.
    /// Works at login/lock screens where clipboard sync can't.
    pub async fn type_text(&self, text: &str) -> Result<(), Error> {
        // Release all modifiers first. If this was triggered by a chord
        // (Ctrl+Shift+V), the user's physical modifier keydowns were already
        // forwarded, and the remote would read every keysym below as a
        // Ctrl+Shift+<key> shortcut instead of text.
        const MODIFIERS: [u32; 8] = [
            0xFFE1, 0xFFE2, // Shift_L/R
            0xFFE3, 0xFFE4, // Control_L/R
            0xFFE9, 0xFFEA, // Alt_L/R
            0xFFEB, 0xFFEC, // Super_L/R
        ];
        for m in MODIFIERS {
            self.send_key(m, false).await?;
        }
        let normalized = text.replace("\r\n", "\n");
        for c in normalized.chars() {
            let Some(ks) = keysym::char_to_keysym(c) else {
                continue;
            };
            self.send_key(ks, true).await?;
            self.send_key(ks, false).await?;
            // pace keystrokes so slow servers don't drop or reorder them
            sleep(Duration::from_millis(8)).await;
        }
        Ok(())
    }

    pub async fn request_update(&self, incremental: bool) -> Result<(), Error> {
        let (w, h) = {
            let fb = self.0.fb.lock().unwrap();
            (fb.width, fb.height)
        };
        let mut msg = [3u8, incremental as u8, 0, 0, 0, 0, 0, 0, 0, 0];
        msg[6..8].copy_from_slice(&w.to_be_bytes());
        msg[8..10].copy_from_slice(&h.to_be_bytes());
        self.0.writer.lock().await.write_all(&msg).await?;
        Ok(())
    }

    /// PNG snapshot of the current framebuffer, for the Agent Bridge.
    pub fn screenshot_png(&self) -> Result<Vec<u8>, Error> {
        self.0.fb.lock().unwrap().to_png()
    }

    pub fn dims(&self) -> (u16, u16) {
        let fb = self.0.fb.lock().unwrap();
        (fb.width, fb.height)
    }

    pub fn remote_clipboard(&self) -> String {
        self.0.remote_clipboard.lock().unwrap().clone()
    }

    pub fn host(&self) -> &str {
        &self.0.host
    }

    pub fn port(&self) -> u16 {
        self.0.port
    }

    /// Mark this tab visible/hidden. A hidden tab stops requesting incremental
    /// updates (the read loop stops re-arming after the current one), so the
    /// server goes quiet and no bandwidth is used. Showing it again kicks a
    /// fresh full-frame request via `request_update(false)`.
    pub fn set_active(&self, active: bool) {
        self.0.active.store(active, Ordering::SeqCst);
    }

    pub fn is_active(&self) -> bool {
        self.0.active.load(Ordering::SeqCst)
    }

    /// Send our clipboard to the remote via the standard ClientCutText path
    /// (Latin-1, per the RFB spec).
    pub async fn set_remote_clipboard(&self, text: &str) -> Result<(), Error> {
        let latin1: Vec<u8> = text.chars().map(|c| c as u8).collect();
        let mut msg = vec![6u8, 0, 0, 0];
        msg.extend_from_slice(&(latin1.len() as u32).to_be_bytes());
        msg.extend_from_slice(&latin1);
        self.0.writer.lock().await.write_all(&msg).await?;
        Ok(())
    }

    pub async fn shutdown(&self) {
        self.0.closed.store(true, Ordering::SeqCst);
        let _ = self.0.writer.lock().await.shutdown().await;
    }
}

async fn read_string(r: &mut OwnedReadHalf) -> Result<String, Error> {
    let len = r.read_u32().await?;
    if len > 1 << 20 {
        return Err("server sent an implausibly long string".into());
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

pub async fn connect(
    app: AppHandle,
    frames: FrameChannel,
    session_id: u32,
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
) -> Result<(SessionHandle, ServerInfo), Error> {
    let stream = timeout(
        Duration::from_secs(10),
        TcpStream::connect((host.as_str(), port)),
    )
    .await
    .map_err(|_| format!("connection to {host}:{port} timed out"))??;
    stream.set_nodelay(true)?;
    let (mut r, mut w) = stream.into_split();

    // --- Version handshake ---
    let mut ver = [0u8; 12];
    r.read_exact(&mut ver).await?;
    if !ver.starts_with(b"RFB ") {
        return Err("not an RFB (VNC) server".into());
    }
    let major: u32 = std::str::from_utf8(&ver[4..7])?.parse()?;
    let minor: u32 = std::str::from_utf8(&ver[8..11])?.parse()?;
    // macOS Screen Sharing reports 3.889; anything >= 3.8 is negotiated as 3.8
    if major < 3 || (major == 3 && minor < 8) {
        return Err(format!("server only speaks RFB {major}.{minor}; Seance requires 3.8+").into());
    }
    w.write_all(b"RFB 003.008\n").await?;

    // --- Security handshake ---
    let ntypes = r.read_u8().await?;
    if ntypes == 0 {
        let reason = read_string(&mut r).await?;
        return Err(format!("server refused connection: {reason}").into());
    }
    let mut types = vec![0u8; ntypes as usize];
    r.read_exact(&mut types).await?;
    let has_username = username.as_deref().is_some_and(|u| !u.is_empty());
    let has_password = password.as_deref().is_some_and(|p| !p.is_empty());
    let has_creds = has_username || has_password;
    let offers = |t: u8| types.contains(&t);
    let no_sec = || -> Error {
        format!(
            "no mutually supported security type (server offered {types:?}; \
             Seance supports None, VNC auth, and Apple auth)"
        )
        .into()
    };
    // Security-type preference. When the operator supplied credentials we never
    // silently fall to None on a server that *also* offers real auth — that
    // would be a downgrade to an unauthenticated session. Apple DH is preferred
    // over VNC auth's weak legacy DES when a username is present (macOS
    // accounts). With no credentials, None is the natural pick for a no-auth
    // server.
    let sec = if has_creds {
        if has_username && offers(30) {
            30u8
        } else if offers(2) {
            2u8
        } else if offers(30) {
            30u8
        } else if offers(1) {
            1u8 // server genuinely offers no authentication at all
        } else {
            return Err(no_sec());
        }
    } else if offers(1) {
        1u8
    } else if offers(2) {
        2u8
    } else if offers(30) {
        30u8
    } else {
        return Err(no_sec());
    };
    if sec == 30 && !has_username {
        return Err(
            "this server requires Apple authentication (macOS Screen Sharing): \
             enter the Mac account's username and password"
                .into(),
        );
    }
    let security = match sec {
        2 => "vnc-auth",
        30 => "apple-dh",
        _ => "none",
    };
    w.write_all(&[sec]).await?;

    if sec == 2 {
        let mut challenge = [0u8; 16];
        r.read_exact(&mut challenge).await?;
        let response = des_auth::encrypt_challenge(&password.unwrap_or_default(), &challenge);
        w.write_all(&response).await?;
    } else if sec == 30 {
        let generator = r.read_u16().await?;
        let key_len = r.read_u16().await? as usize;
        if key_len == 0 || key_len > 8192 {
            return Err(format!("implausible Apple DH key length {key_len}").into());
        }
        let mut prime = vec![0u8; key_len];
        r.read_exact(&mut prime).await?;
        let mut server_public = vec![0u8; key_len];
        r.read_exact(&mut server_public).await?;
        let resp = apple_auth::auth_response(
            generator,
            &prime,
            &server_public,
            &username.unwrap_or_default(),
            &password.unwrap_or_default(),
        );
        w.write_all(&resp.ciphertext).await?;
        w.write_all(&resp.client_public).await?;
    }

    let result = r.read_u32().await?;
    if result != 0 {
        let reason = read_string(&mut r)
            .await
            .unwrap_or_else(|_| "wrong password?".into());
        return Err(format!("authentication failed: {reason}").into());
    }

    // --- ClientInit / ServerInit ---
    w.write_all(&[1]).await?; // shared session
    let width = r.read_u16().await?;
    let height = r.read_u16().await?;
    check_dims(width, height)?;
    let mut server_pf = [0u8; 16];
    r.read_exact(&mut server_pf).await?;
    let name = read_string(&mut r).await?;

    // --- SetPixelFormat: 32bpp true-color, BGRA in little-endian memory ---
    let mut pf = [0u8; 20];
    pf[4] = 32; // bits-per-pixel
    pf[5] = 24; // depth
    pf[6] = 0; // big-endian flag
    pf[7] = 1; // true-colour flag
    pf[8..10].copy_from_slice(&255u16.to_be_bytes()); // red max
    pf[10..12].copy_from_slice(&255u16.to_be_bytes()); // green max
    pf[12..14].copy_from_slice(&255u16.to_be_bytes()); // blue max
    pf[14] = 16; // red shift
    pf[15] = 8; // green shift
    pf[16] = 0; // blue shift
    w.write_all(&pf).await?;

    // --- SetEncodings, preference order: ZRLE, CopyRect, Raw + pseudo ---
    let encodings: [i32; 5] = [16, 1, 0, -239, -223];
    let mut msg = vec![2u8, 0];
    msg.extend_from_slice(&(encodings.len() as u16).to_be_bytes());
    for e in encodings {
        msg.extend_from_slice(&e.to_be_bytes());
    }
    w.write_all(&msg).await?;

    let handle = SessionHandle(Arc::new(Inner {
        writer: Mutex::new(w),
        closed: AtomicBool::new(false),
        fb: std::sync::Mutex::new(Framebuffer::new(width, height)),
        remote_clipboard: std::sync::Mutex::new(String::new()),
        session_id,
        host,
        port,
        active: AtomicBool::new(true),
    }));

    // initial full-screen update
    handle.request_update(false).await?;

    let reader_handle = handle.clone();
    tauri::async_runtime::spawn(async move {
        let res = read_loop(&app, &frames, &mut r, &reader_handle).await;
        if !reader_handle.0.closed.load(Ordering::SeqCst) {
            let reason = match res {
                Ok(()) => "connection closed by server".to_string(),
                Err(e) => e.to_string(),
            };
            let _ = app.emit(
                "rfb-disconnected",
                serde_json::json!({ "id": session_id, "reason": reason }),
            );
        }
    });

    Ok((
        handle,
        ServerInfo {
            width,
            height,
            name,
            security: security.to_string(),
            encrypted: false,
        },
    ))
}

/// Inflate a chunk of the session's continuous zlib stream (ZRLE shares one
/// dictionary across all rects, so the Decompress state must persist).
/// `max_out` caps the decompressed size, so a zlib bomb (tiny compressed input
/// that expands to gigabytes) is rejected rather than exhausting memory.
fn inflate(z: &mut flate2::Decompress, input: &[u8], max_out: usize) -> Result<Vec<u8>, Error> {
    // Reserve modestly and grow; never trust the compressed length to size the
    // reservation (input.len() * 8 on a 64 MB rect would pre-allocate 512 MB).
    let mut out = Vec::with_capacity((input.len() * 4).min(1 << 20).min(max_out.max(1)));
    let mut buf = [0u8; 64 * 1024];
    let mut consumed = 0usize;
    loop {
        let before_in = z.total_in();
        let before_out = z.total_out();
        z.decompress(&input[consumed..], &mut buf, flate2::FlushDecompress::None)
            .map_err(|e| format!("zlib error: {e}"))?;
        let took = (z.total_in() - before_in) as usize;
        let produced = (z.total_out() - before_out) as usize;
        consumed += took;
        out.extend_from_slice(&buf[..produced]);
        if out.len() > max_out {
            return Err("ZRLE decompressed output exceeds its rect's size limit".into());
        }
        if took == 0 && produced == 0 {
            if consumed < input.len() {
                return Err("zlib stream stalled".into());
            }
            break;
        }
        if consumed >= input.len() && produced < buf.len() {
            break;
        }
    }
    Ok(out)
}

async fn read_loop(
    app: &AppHandle,
    frames: &FrameChannel,
    r: &mut OwnedReadHalf,
    handle: &SessionHandle,
) -> Result<(), Error> {
    let session = handle.0.session_id;
    let mut zlib = flate2::Decompress::new(true);
    loop {
        let msg_type = r.read_u8().await?;
        match msg_type {
            // FramebufferUpdate
            0 => {
                r.read_u8().await?; // padding
                let nrects = r.read_u16().await?;
                // dims can change mid-update via DesktopSize; re-read per rect
                for _ in 0..nrects {
                    let x = r.read_u16().await?;
                    let y = r.read_u16().await?;
                    let w = r.read_u16().await?;
                    let h = r.read_u16().await?;
                    let encoding = r.read_i32().await?;
                    let (fbw, fbh) = handle.dims();
                    match encoding {
                        // Raw
                        0 => {
                            check_rect(fbw, fbh, x, y, w, h)?;
                            let mut buf = vec![0u8; w as usize * h as usize * 4];
                            r.read_exact(&mut buf).await?;
                            // BGRA -> RGBA, force opaque alpha
                            for px in buf.chunks_exact_mut(4) {
                                px.swap(0, 2);
                                px[3] = 255;
                            }
                            handle.0.fb.lock().unwrap().blit(x, y, w, h, &buf);
                            frames.send_rect(session, x, y, w, h, &buf);
                        }
                        // CopyRect: frontend copies the region within its canvas
                        1 => {
                            let src_x = r.read_u16().await?;
                            let src_y = r.read_u16().await?;
                            handle
                                .0
                                .fb
                                .lock()
                                .unwrap()
                                .copy_rect(x, y, w, h, src_x, src_y);
                            frames.send_copyrect(session, x, y, w, h, src_x, src_y);
                        }
                        // ZRLE
                        16 => {
                            check_rect(fbw, fbh, x, y, w, h)?;
                            let clen = r.read_u32().await? as usize;
                            if clen > MAX_ZRLE_COMPRESSED {
                                return Err("ZRLE rect implausibly large".into());
                            }
                            let mut comp = vec![0u8; clen];
                            r.read_exact(&mut comp).await?;
                            // A ZRLE rect decodes to at most its padded-to-64 tile
                            // area of pixel data plus small per-tile headers.
                            let max_out = (w as usize + 64) * (h as usize + 64) * 4 + 4096;
                            let raw = inflate(&mut zlib, &comp, max_out)?;
                            let rgba = zrle::decode(&raw, w as usize, h as usize)?;
                            handle.0.fb.lock().unwrap().blit(x, y, w, h, &rgba);
                            frames.send_rect(session, x, y, w, h, &rgba);
                        }
                        // Cursor pseudo-encoding: render the pointer locally.
                        // x,y are the hotspot; payload is pixels + 1-bit mask.
                        -239 => {
                            if w > MAX_CURSOR_DIM || h > MAX_CURSOR_DIM {
                                return Err(format!("cursor {w}x{h} exceeds limit").into());
                            }
                            let npx = w as usize * h as usize;
                            let mut pixels = vec![0u8; npx * 4];
                            r.read_exact(&mut pixels).await?;
                            let mask_stride = (w as usize + 7) / 8;
                            let mut mask = vec![0u8; mask_stride * h as usize];
                            r.read_exact(&mut mask).await?;
                            for i in 0..npx {
                                let (mx, my) = (i % w as usize, i / w as usize);
                                let visible =
                                    (mask[my * mask_stride + mx / 8] >> (7 - mx % 8)) & 1 == 1;
                                let px = &mut pixels[i * 4..i * 4 + 4];
                                px.swap(0, 2); // BGRA -> RGBA
                                px[3] = if visible { 255 } else { 0 };
                            }
                            frames.send_cursor(session, x, y, w, h, &pixels);
                        }
                        // DesktopSize pseudo-encoding
                        -223 => {
                            check_dims(w, h)?;
                            handle.0.fb.lock().unwrap().resize(w, h);
                            frames.send_resize(session, w, h);
                        }
                        other => {
                            return Err(format!("server sent unrequested encoding {other}").into())
                        }
                    }
                }
                // keep the stream flowing — but only while this tab is visible.
                // A hidden tab stops re-arming, so the server goes quiet and the
                // read loop simply blocks until the tab is shown again (which
                // kicks a fresh request via set_active + request_update).
                if handle.0.active.load(Ordering::SeqCst) {
                    handle.request_update(true).await?;
                }
            }
            // SetColourMapEntries (shouldn't happen in true-color, but consume it)
            1 => {
                r.read_u8().await?;
                r.read_u16().await?;
                let n = r.read_u16().await?;
                let mut skip = vec![0u8; n as usize * 6];
                r.read_exact(&mut skip).await?;
            }
            // Bell
            2 => {
                let _ = app.emit("rfb-bell", ());
            }
            // ServerCutText
            3 => {
                let mut pad = [0u8; 3];
                r.read_exact(&mut pad).await?;
                let len = r.read_i32().await?;
                let n = len.unsigned_abs() as usize;
                if n > MAX_CLIPBOARD {
                    return Err(format!("clipboard payload {n} bytes exceeds limit").into());
                }
                if len >= 0 {
                    let mut buf = vec![0u8; n];
                    r.read_exact(&mut buf).await?;
                    // spec says Latin-1
                    let text: String = buf.iter().map(|&b| b as char).collect();
                    *handle.0.remote_clipboard.lock().unwrap() = text.clone();
                    let _ = app.clipboard().write_text(text);
                    let _ = app.emit("rfb-cut-text", ());
                } else {
                    // negative length = extended clipboard (RFC 6143 extension); skip it
                    let mut buf = vec![0u8; n];
                    r.read_exact(&mut buf).await?;
                }
            }
            other => return Err(format!("unknown server message type {other}").into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_dims_rejects_absurd_but_allows_real_desktops() {
        assert!(check_dims(1920, 1080).is_ok());
        assert!(check_dims(7680, 4320).is_ok()); // 8K
        assert!(check_dims(0, 1080).is_err()); // zero
        assert!(check_dims(u16::MAX, u16::MAX).is_err()); // ~17 TB of RGBA
        assert!(check_dims(16384, 16384).is_err()); // area cap (dims ok, area not)
    }

    #[test]
    fn check_rect_rejects_out_of_bounds() {
        assert!(check_rect(1920, 1080, 0, 0, 1920, 1080).is_ok());
        assert!(check_rect(1920, 1080, 100, 100, 100, 100).is_ok());
        assert!(check_rect(1920, 1080, 0, 0, 65535, 65535).is_err()); // huge rect
        assert!(check_rect(1920, 1080, 1900, 0, 100, 10).is_err()); // x+w past edge
        assert!(check_rect(1920, 1080, 0, 1080, 10, 1).is_err()); // y+h past edge
    }

    #[test]
    fn inflate_rejects_a_zlib_bomb() {
        // Compress a large run of zeros, then demand a tiny max_out: the bomb
        // must be rejected mid-inflate rather than fully expanded.
        use std::io::Write;
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        enc.write_all(&vec![0u8; 4 << 20]).unwrap(); // 4 MB -> a few KB compressed
        let bomb = enc.finish().unwrap();
        let mut z = flate2::Decompress::new(true);
        assert!(inflate(&mut z, &bomb, 64 << 10).is_err()); // 64 KB cap
    }

    /// Live probe of Apple DH auth (type 30) against a real macOS Screen
    /// Sharing server, using deliberately wrong credentials: a clean
    /// SecurityResult failure proves the DH exchange and credential-block
    /// framing are wire-correct (a malformed response desyncs or hangs the
    /// connection instead). Run explicitly with:
    ///   SEANCE_APPLE_HOST=<mac-ip> cargo test apple_dh_live -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn apple_dh_live_probe_rejects_wrong_password() {
        let host = std::env::var("SEANCE_APPLE_HOST").expect("set SEANCE_APPLE_HOST");
        let stream = TcpStream::connect((host.as_str(), 5900)).await.unwrap();
        let (mut r, mut w) = stream.into_split();

        let mut ver = [0u8; 12];
        r.read_exact(&mut ver).await.unwrap();
        assert!(ver.starts_with(b"RFB "), "not an RFB server");
        w.write_all(b"RFB 003.008\n").await.unwrap();

        let ntypes = r.read_u8().await.unwrap();
        assert!(ntypes > 0, "server refused connection");
        let mut types = vec![0u8; ntypes as usize];
        r.read_exact(&mut types).await.unwrap();
        println!("server offered security types {types:?}");
        assert!(types.contains(&30), "server does not offer Apple DH auth");
        w.write_all(&[30]).await.unwrap();

        let generator = r.read_u16().await.unwrap();
        let key_len = r.read_u16().await.unwrap() as usize;
        println!("generator {generator}, key length {key_len}");
        assert!(key_len > 0 && key_len <= 8192);
        let mut prime = vec![0u8; key_len];
        r.read_exact(&mut prime).await.unwrap();
        let mut server_public = vec![0u8; key_len];
        r.read_exact(&mut server_public).await.unwrap();

        let resp = apple_auth::auth_response(
            generator,
            &prime,
            &server_public,
            "seance-probe",
            "definitely-wrong",
        );
        w.write_all(&resp.ciphertext).await.unwrap();
        w.write_all(&resp.client_public).await.unwrap();

        let result = r.read_u32().await.unwrap();
        println!("SecurityResult: {result}");
        assert_ne!(result, 0, "wrong password unexpectedly accepted");
        // RFB 3.8 sends a reason string after failure; it arriving intact is
        // further proof we stayed in sync.
        let reason = read_string(&mut r).await.unwrap();
        println!("server reason: {reason}");
    }
}
