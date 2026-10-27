import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen, UnlistenFn } from "@tauri-apps/api/event";
import { randomQuip } from "./quips";
import { eventToKeysym } from "./keysym";
import AgentPanel from "./AgentPanel";

interface ServerInfo {
  width: number;
  height: number;
  name: string;
  security: string; // "none" | "vnc-auth" | "apple-dh"
  encrypted: boolean;
}

// Honest security posture for a session. Raw VNC is "compatibility mode": how
// safe it is depends on the server and network, and Seance shouldn't pretend
// otherwise.
function SecurityBadge({ session }: { session: Session }) {
  const auth =
    session.security === "vnc-auth"
      ? "legacy VNC"
      : session.security === "apple-dh"
      ? "Apple auth"
      : "no-auth";
  const level =
    session.security === "none" ? "bad" : session.encrypted ? "ok" : "warn";
  const enc = session.encrypted ? "encrypted" : "unencrypted";
  const title =
    `${auth === "no-auth" ? "No authentication" : auth}, ${enc} transport. ` +
    "Compatibility mode — security depends on your VNC server and network.";
  return (
    <span className={`posture posture-${level}`} title={title}>
      {auth === "no-auth" ? "⚠ no-auth" : auth} · {enc}
    </span>
  );
}

// A live session shown as a tab.
interface Session {
  id: number;
  host: string;
  port: number;
  username: string | null;
  name: string;
  width: number;
  height: number;
  security: string;
  encrypted: boolean;
}

/// What we need to offer one-click reconnect after a session drops.
interface DroppedSession {
  host: string;
  port: number;
  username: string | null;
  name: string;
  reason: string;
}

// Binary draw ops from the loopback WebSocket. Layout (little-endian):
// u8 op, u32 session, then per-op payload — see src-tauri/src/frames.rs.
const OP_RECT = 0;
const OP_COPYRECT = 1;
const OP_CURSOR = 2;
const OP_RESIZE = 3;

function applyOp(
  canvas: HTMLCanvasElement,
  ctx: CanvasRenderingContext2D,
  buf: ArrayBuffer,
  sessionId: number,
  onResize: (id: number, w: number, h: number) => void,
) {
  const dv = new DataView(buf);
  switch (dv.getUint8(0)) {
    case OP_RECT: {
      const x = dv.getUint16(5, true);
      const y = dv.getUint16(7, true);
      const w = dv.getUint16(9, true);
      const h = dv.getUint16(11, true);
      ctx.putImageData(new ImageData(new Uint8ClampedArray(buf, 13), w, h), x, y);
      break;
    }
    case OP_COPYRECT: {
      const x = dv.getUint16(5, true);
      const y = dv.getUint16(7, true);
      const w = dv.getUint16(9, true);
      const h = dv.getUint16(11, true);
      const srcX = dv.getUint16(13, true);
      const srcY = dv.getUint16(15, true);
      ctx.drawImage(canvas, srcX, srcY, w, h, x, y, w, h);
      break;
    }
    case OP_CURSOR: {
      const hotX = dv.getUint16(5, true);
      const hotY = dv.getUint16(7, true);
      const w = dv.getUint16(9, true);
      const h = dv.getUint16(11, true);
      if (w === 0 || h === 0) {
        canvas.style.cursor = "none";
        break;
      }
      const tmp = document.createElement("canvas");
      tmp.width = w;
      tmp.height = h;
      tmp
        .getContext("2d")!
        .putImageData(new ImageData(new Uint8ClampedArray(buf, 13), w, h), 0, 0);
      canvas.style.cursor = `url(${tmp.toDataURL()}) ${hotX} ${hotY}, default`;
      break;
    }
    case OP_RESIZE: {
      const w = dv.getUint16(5, true);
      const h = dv.getUint16(7, true);
      canvas.width = w;
      canvas.height = h;
      onResize(sessionId, w, h);
      invoke("request_update", { sessionId, incremental: false }).catch(() => {});
      break;
    }
  }
}

// e.buttons (L=1, R=2, M=4) -> RFB mask (L=1, M=2, R=4)
function toRfbButtons(buttons: number): number {
  return (buttons & 1 ? 1 : 0) | (buttons & 4 ? 2 : 0) | (buttons & 2 ? 4 : 0);
}

function pointerFromEvent(canvas: HTMLCanvasElement, clientX: number, clientY: number) {
  const rect = canvas.getBoundingClientRect();
  // object-fit: contain letterboxes the content; map through the real content rect
  const scale = Math.min(rect.width / canvas.width, rect.height / canvas.height);
  const offX = (rect.width - canvas.width * scale) / 2;
  const offY = (rect.height - canvas.height * scale) / 2;
  const x = Math.round((clientX - rect.left - offX) / scale);
  const y = Math.round((clientY - rect.top - offY) / scale);
  return {
    x: Math.max(0, Math.min(canvas.width - 1, x)),
    y: Math.max(0, Math.min(canvas.height - 1, y)),
  };
}

const RECENT_KEY = "seance.recentHosts"; // legacy — migrated into saved hosts

interface SavedHost {
  name: string;
  host: string;
  port: number;
  username: string | null;
  has_password: boolean;
  group: string | null;
}

export default function App() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [activeId, setActiveId] = useState<number | null>(null);
  // the tab the Agent Bridge is pinned to (null = it follows the active tab).
  // Lives here, not in AgentPanel, because the tab bar marks it and the panel
  // unmounts while the connection form is showing.
  const [agentPinned, setAgentPinned] = useState<number | null>(null);
  const [adding, setAdding] = useState(false);
  const [connecting, setConnecting] = useState(false);

  const [host, setHost] = useState("");
  const [port, setPort] = useState("5900");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [remember, setRemember] = useState(false);
  const [group, setGroup] = useState("");
  const [error, setError] = useState("");
  const [quip, setQuip] = useState(randomQuip());
  const [pasteOpen, setPasteOpen] = useState(false);
  const [pasteText, setPasteText] = useState("");
  const [toast, setToast] = useState("");
  const [savedHosts, setSavedHosts] = useState<SavedHost[]>([]);
  const [savedOpen, setSavedOpen] = useState(
    () => localStorage.getItem("seance.savedOpen") !== "false",
  );
  const [groupsOpen, setGroupsOpen] = useState<Record<string, boolean>>(() =>
    JSON.parse(localStorage.getItem("seance.groupsOpen") ?? "{}"),
  );
  const [editing, setEditing] = useState<SavedHost | null>(null);
  const [editName, setEditName] = useState("");
  const [editGroup, setEditGroup] = useState("");
  const [dropped, setDropped] = useState<DroppedSession | null>(null);

  const toggleSaved = useCallback(() => {
    setSavedOpen((o) => {
      localStorage.setItem("seance.savedOpen", String(!o));
      return !o;
    });
  }, []);

  const toggleGroup = useCallback((name: string) => {
    setGroupsOpen((m) => {
      const next = { ...m, [name]: !(m[name] ?? true) };
      localStorage.setItem("seance.groupsOpen", JSON.stringify(next));
      return next;
    });
  }, []);

  const groupNames = [
    ...new Set(savedHosts.map((s) => s.group).filter((g): g is string => !!g)),
  ].sort();

  // load saved hosts; fold any pre-connection-manager recents into them once
  useEffect(() => {
    (async () => {
      let hosts = await invoke<SavedHost[]>("hosts_list").catch(() => []);
      const legacy: string[] = JSON.parse(localStorage.getItem(RECENT_KEY) ?? "[]");
      for (const r of legacy) {
        const [h, p] = r.includes(":") ? r.split(":") : [r, "5900"];
        if (!hosts.some((x) => x.host === h && x.port === Number(p))) {
          hosts = await invoke<SavedHost[]>("hosts_save", {
            entry: {
              name: h,
              host: h,
              port: Number(p),
              username: null,
              has_password: false,
              group: null,
            },
            password: null,
          }).catch(() => hosts);
        }
      }
      localStorage.removeItem(RECENT_KEY);
      setSavedHosts(hosts);
    })();
  }, []);

  const canvasRefs = useRef<Map<number, HTMLCanvasElement>>(new Map());
  // Tabs whose connection dropped before the tab was added: the drop event
  // can beat the connect result. Ids are never reused, so such a tab is
  // refused (and its backend handle released) instead of lingering dead.
  const droppedIds = useRef<Set<number>>(new Set());
  const addSession = useCallback((s: Session) => {
    if (droppedIds.current.has(s.id)) {
      invoke("disconnect", { id: s.id }).catch(() => {});
      return false;
    }
    setSessions((ss) => [...ss, s]);
    return true;
  }, []);
  const activeIdRef = useRef<number | null>(null);
  activeIdRef.current = activeId;
  const pasteOpenRef = useRef(pasteOpen);
  pasteOpenRef.current = pasteOpen;

  const activeSession = sessions.find((s) => s.id === activeId) ?? null;
  const showForm = connecting || adding || sessions.length === 0;

  const showToast = useCallback((msg: string) => {
    setToast(msg);
    window.setTimeout(() => setToast(""), 2500);
  }, []);

  const onResize = useCallback((id: number, w: number, h: number) => {
    setSessions((ss) => ss.map((s) => (s.id === id ? { ...s, width: w, height: h } : s)));
  }, []);
  const onResizeRef = useRef(onResize);
  onResizeRef.current = onResize;

  // rotate quips while connecting
  useEffect(() => {
    if (!connecting) return;
    const t = setInterval(() => setQuip((q) => randomQuip(q)), 2200);
    return () => clearInterval(t);
  }, [connecting]);

  // binary framebuffer channel: route each op to its session's canvas, painted
  // once per animation frame
  useEffect(() => {
    let ws: WebSocket | null = null;
    let raf = 0;
    let queue: ArrayBuffer[] = [];
    let disposed = false;

    const paint = () => {
      raf = 0;
      const ops = queue;
      queue = [];
      for (const buf of ops) {
        const id = new DataView(buf).getUint32(1, true);
        const canvas = canvasRefs.current.get(id);
        const ctx = canvas?.getContext("2d");
        if (canvas && ctx) applyOp(canvas, ctx, buf, id, onResizeRef.current);
      }
    };

    invoke<string>("frame_endpoint").then((url) => {
      if (disposed) return;
      ws = new WebSocket(url);
      ws.binaryType = "arraybuffer";
      ws.onmessage = (e) => {
        queue.push(e.data as ArrayBuffer);
        if (!raf) raf = requestAnimationFrame(paint);
      };
    });

    return () => {
      disposed = true;
      if (raf) cancelAnimationFrame(raf);
      ws?.close();
    };
  }, []);

  // lifecycle events
  useEffect(() => {
    const subs: Promise<UnlistenFn>[] = [
      listen<{ id: number; reason: string }>("rfb-disconnected", (e) => {
        const { id, reason } = e.payload;
        droppedIds.current.add(id);
        canvasRefs.current.delete(id);
        // drop the dead handle so the Agent Bridge stops listing the tab
        invoke("disconnect", { id }).catch(() => {});
        setSessions((ss) => {
          const gone = ss.find((s) => s.id === id);
          if (gone) {
            setDropped({
              host: gone.host,
              port: gone.port,
              username: gone.username,
              name: gone.name,
              reason,
            });
          }
          const next = ss.filter((s) => s.id !== id);
          setActiveId((cur) => {
            if (cur !== id) return cur;
            const fallback = next[next.length - 1]?.id ?? null;
            if (fallback != null) invoke("set_active", { id: fallback }).catch(() => {});
            return fallback;
          });
          return next;
        });
      }),
      // the Agent Bridge opened a saved host in a background tab; the
      // operator's current view stays put
      listen<{
        id: number;
        info: ServerInfo;
        host: string;
        port: number;
        username: string | null;
      }>("agent-session-opened", (e) => {
        const { id, info, host, port, username } = e.payload;
        const added = addSession({
          id,
          host,
          port,
          username,
          name: info.name,
          width: info.width,
          height: info.height,
          security: info.security,
          encrypted: info.encrypted,
        });
        if (added) showToast(`Agent opened ${info.name || host}`);
      }),
      // the agent retargeted itself (switch_tab / open_saved_host)
      listen<{ id: number }>("agent-pinned", (e) => {
        setAgentPinned(e.payload.id);
      }),
      listen("rfb-cut-text", () => {
        showToast("Remote clipboard copied");
      }),
    ];
    return () => subs.forEach((s) => s.then((f) => f()));
  }, [showToast, addSession]);

  const doConnect = useCallback(
    async (
      h: string,
      p: string,
      user: string,
      pw: string,
      savePassword: boolean,
      grp?: string,
    ) => {
      setError("");
      setQuip(randomQuip());
      setConnecting(true);
      try {
        const res = await invoke<{ id: number; info: ServerInfo }>("connect", {
          host: h,
          port: parseInt(p, 10) || 5900,
          username: user || null,
          password: pw || null,
        });
        const s: Session = {
          id: res.id,
          host: h,
          port: parseInt(p, 10) || 5900,
          username: user || null,
          name: res.info.name,
          width: res.info.width,
          height: res.info.height,
          security: res.info.security,
          encrypted: res.info.encrypted,
        };
        if (!addSession(s)) throw new Error("connection closed by the host");
        setActiveId(res.id);
        setAdding(false);
        setConnecting(false);
        setPassword("");
        setDropped(null);
        // a successful connect is worth remembering: upsert the saved host
        // (password only when asked — it goes to the OS credential store)
        invoke<SavedHost[]>("hosts_save", {
          entry: {
            name: res.info.name || h,
            host: h,
            port: parseInt(p, 10) || 5900,
            username: user || null,
            has_password: false,
            // empty means "leave as-is" — an existing entry keeps its folder
            group: grp?.trim() || null,
          },
          password: savePassword && pw ? pw : null,
        })
          .then(setSavedHosts)
          .catch(() => {});
      } catch (err) {
        setConnecting(false);
        setError(String(err));
        showToast(String(err)); // visible even when the lobby form isn't
      }
    },
    [showToast, addSession],
  );

  const connectSaved = useCallback(
    async (s: SavedHost) => {
      setHost(s.host);
      setPort(String(s.port));
      setUsername(s.username ?? "");
      if (s.has_password) {
        setError("");
        setQuip(randomQuip());
        setConnecting(true);
        try {
          const res = await invoke<{ id: number; info: ServerInfo }>("connect_stored", {
            host: s.host,
            port: s.port,
            username: s.username,
          });
          const session: Session = {
            id: res.id,
            host: s.host,
            port: s.port,
            username: s.username,
            name: res.info.name,
            width: res.info.width,
            height: res.info.height,
            security: res.info.security,
            encrypted: res.info.encrypted,
          };
          if (!addSession(session)) throw new Error("connection closed by the host");
          setActiveId(res.id);
          setAdding(false);
          setConnecting(false);
          setPassword("");
          setDropped(null);
        } catch (err) {
          setConnecting(false);
          setError(String(err));
          showToast(String(err));
        }
        return;
      }
      const pw = password;
      setPassword("");
      doConnect(s.host, String(s.port), s.username ?? "", pw, false);
    },
    [password, doConnect, showToast, addSession],
  );

  const deleteSaved = useCallback((s: SavedHost) => {
    invoke<SavedHost[]>("hosts_delete", { host: s.host, port: s.port })
      .then(setSavedHosts)
      .catch(() => {});
  }, []);

  const chipFor = (s: SavedHost) => (
    <button
      key={`${s.host}:${s.port}`}
      type="button"
      className="chip"
      title={`${s.host}:${s.port}${s.username ? ` as ${s.username}` : ""}${
        s.has_password ? " (password saved)" : ""
      }`}
      onClick={() => connectSaved(s)}
    >
      {s.name || s.host}
      {s.has_password && <span className="chip-key">🔑</span>}
      <span
        className="chip-edit"
        title="Rename or move to a group"
        onClick={(e) => {
          e.stopPropagation();
          openEdit(s);
        }}
      >
        ✎
      </span>
      <span
        className="chip-x"
        title="Forget this host"
        onClick={(e) => {
          e.stopPropagation();
          deleteSaved(s);
        }}
      >
        ×
      </span>
    </button>
  );

  const openEdit = useCallback((s: SavedHost) => {
    setEditing(s);
    setEditName(s.name);
    setEditGroup(s.group ?? "");
  }, []);

  const saveEdit = useCallback(() => {
    if (!editing) return;
    invoke<SavedHost[]>("hosts_update_meta", {
      host: editing.host,
      port: editing.port,
      name: editName,
      group: editGroup,
    })
      .then(setSavedHosts)
      .catch(() => {});
    setEditing(null);
  }, [editing, editName, editGroup]);

  /// One-click reconnect to the session that just dropped, reusing the saved
  /// password when there is one.
  const reconnect = useCallback(async () => {
    if (!dropped) return;
    const d = dropped;
    setDropped(null);
    setError("");
    setQuip(randomQuip());
    setConnecting(true);
    try {
      const res = await invoke<{ id: number; info: ServerInfo }>("connect_stored", {
        host: d.host,
        port: d.port,
        username: d.username,
      });
      const session: Session = {
        id: res.id,
        host: d.host,
        port: d.port,
        username: d.username,
        name: res.info.name,
        width: res.info.width,
        height: res.info.height,
        security: res.info.security,
        encrypted: res.info.encrypted,
      };
      if (!addSession(session)) throw new Error("connection closed by the host");
      setActiveId(res.id);
      setAdding(false);
      setConnecting(false);
    } catch (err) {
      setConnecting(false);
      setError(String(err));
      showToast(String(err));
    }
  }, [dropped, showToast, addSession]);

  // once a session's canvas mounts, size it and request a full repaint
  useEffect(() => {
    for (const s of sessions) {
      const canvas = canvasRefs.current.get(s.id);
      if (canvas && (canvas.width !== s.width || canvas.height !== s.height)) {
        canvas.width = s.width;
        canvas.height = s.height;
      }
    }
    if (activeId != null) {
      invoke("request_update", { sessionId: activeId, incremental: false }).catch(() => {});
    }
  }, [sessions, activeId]);

  const changeAgentPin = useCallback((id: number | null) => {
    setAgentPinned(id);
    invoke("set_pinned", { id }).catch(() => {});
  }, []);

  // drop the agent's pin if its tab closed
  useEffect(() => {
    if (agentPinned != null && !sessions.some((s) => s.id === agentPinned)) {
      changeAgentPin(null);
    }
  }, [sessions, agentPinned, changeAgentPin]);

  const selectTab = useCallback((id: number) => {
    setActiveId(id);
    setAdding(false); // clicking a tab also leaves the "new connection" form
    invoke("set_active", { id }).catch(() => {});
  }, []);

  const closeTab = useCallback(async (id: number) => {
    await invoke("disconnect", { id }).catch(() => {});
    canvasRefs.current.delete(id);
    setSessions((ss) => ss.filter((s) => s.id !== id));
    setActiveId((cur) => {
      if (cur !== id) return cur;
      return null; // set_active for the promoted tab is handled by the effect below
    });
  }, []);

  // when the active tab closes, promote the last remaining one
  useEffect(() => {
    if (activeId == null && sessions.length > 0) {
      const next = sessions[sessions.length - 1].id;
      setActiveId(next);
      invoke("set_active", { id: next }).catch(() => {});
    }
  }, [activeId, sessions]);

  const typeClipboard = useCallback(async () => {
    const id = activeIdRef.current;
    if (id == null) return;
    try {
      const count = await invoke<number>("type_clipboard", { sessionId: id });
      if (!count) {
        showToast("Clipboard is empty");
        return;
      }
      showToast(`Typed ${count} characters`);
    } catch {
      setPasteText("");
      setPasteOpen(true);
    }
  }, [showToast]);

  const sendCtrlAltDel = useCallback(async () => {
    const id = activeIdRef.current;
    if (id == null) return;
    const seq: [number, boolean][] = [
      [0xffe3, true],
      [0xffe9, true],
      [0xffff, true],
      [0xffff, false],
      [0xffe9, false],
      [0xffe3, false],
    ];
    for (const [keysym, down] of seq) {
      await invoke("send_key", { sessionId: id, keysym, down }).catch(() => {});
    }
  }, []);

  // keyboard forwarding to the active session
  useEffect(() => {
    if (activeId == null || showForm) return;
    const down = (e: KeyboardEvent) => {
      if (pasteOpenRef.current) return;
      if (e.ctrlKey && e.shiftKey && e.key.toLowerCase() === "v") {
        e.preventDefault();
        typeClipboard();
        return;
      }
      const ks = eventToKeysym(e);
      if (ks !== null) {
        e.preventDefault();
        invoke("send_key", { sessionId: activeId, keysym: ks, down: true }).catch(() => {});
      }
    };
    const up = (e: KeyboardEvent) => {
      if (pasteOpenRef.current) return;
      const ks = eventToKeysym(e);
      if (ks !== null) {
        e.preventDefault();
        invoke("send_key", { sessionId: activeId, keysym: ks, down: false }).catch(() => {});
      }
    };
    window.addEventListener("keydown", down);
    window.addEventListener("keyup", up);
    return () => {
      window.removeEventListener("keydown", down);
      window.removeEventListener("keyup", up);
    };
  }, [activeId, showForm, typeClipboard]);

  const sendPointer = (e: React.MouseEvent<HTMLCanvasElement>, id: number) => {
    const { x, y } = pointerFromEvent(e.currentTarget, e.clientX, e.clientY);
    invoke("send_pointer", { sessionId: id, x, y, buttons: toRfbButtons(e.buttons) }).catch(
      () => {},
    );
  };

  const onWheel = (e: React.WheelEvent<HTMLCanvasElement>, id: number) => {
    const { x, y } = pointerFromEvent(e.currentTarget, e.clientX, e.clientY);
    const base = toRfbButtons(e.buttons);
    const wheelBit = e.deltaY < 0 ? 8 : 16;
    invoke("send_pointer", { sessionId: id, x, y, buttons: base | wheelBit }).catch(() => {});
    invoke("send_pointer", { sessionId: id, x, y, buttons: base }).catch(() => {});
  };

  const cancelAdd = () => {
    setAdding(false);
    setError("");
  };

  return (
    <div className="app">
      <header className="topbar">
        <span className="wordmark">Seance</span>
        <div className="tabs">
          {sessions.map((s) => (
            <div
              key={s.id}
              className={`tab ${s.id === activeId && !showForm ? "tab-active" : ""}`}
              onClick={() => selectTab(s.id)}
              title={`${s.host} — ${s.name}`}
            >
              <span className="tab-label">{s.name || s.host}</span>
              {/* only when pinned: following the active tab can't split views */}
              {s.id === agentPinned && (
                <span className="tab-agent" title="The Agent Bridge acts on this tab">
                  agent
                </span>
              )}
              <button
                className="tab-close"
                onClick={(e) => {
                  e.stopPropagation();
                  closeTab(s.id);
                }}
                title="Close tab"
              >
                ×
              </button>
            </div>
          ))}
          {sessions.length > 0 && (
            <button
              className={`tab-add ${adding ? "tab-active" : ""}`}
              onClick={() => {
                setAdding(true);
                setError("");
              }}
              title="New connection"
            >
              +
            </button>
          )}
        </div>
        {/* The Agent Bridge stays mounted on every screen: it owns the consent
            prompts, and an agent can call tools (open_saved_host) before any
            session exists. Unmounted, its requests would time out unseen. */}
        <div className="toolbar-right">
          {activeSession && !showForm && (
            <>
              <SecurityBadge session={activeSession} />
              <button className="btn" onClick={typeClipboard} title="Ctrl+Shift+V">
                Paste as keystrokes
              </button>
              <button
                className="btn"
                onClick={() => {
                  setPasteText("");
                  setPasteOpen(true);
                }}
                title="Type arbitrary text without touching the clipboard"
              >
                Type text...
              </button>
              <button className="btn" onClick={sendCtrlAltDel}>
                Ctrl+Alt+Del
              </button>
            </>
          )}
          <AgentPanel
            sessions={sessions}
            activeId={activeId}
            pinned={agentPinned}
            onPinChange={changeAgentPin}
          />
          {activeSession && !showForm && (
            <button className="btn btn-danger" onClick={() => closeTab(activeSession.id)}>
              Disconnect
            </button>
          )}
        </div>
      </header>

      <main className="viewport" onContextMenu={(e) => e.preventDefault()}>
        {sessions.map((s) => (
          <canvas
            key={s.id}
            ref={(el) => {
              if (el) canvasRefs.current.set(s.id, el);
              else canvasRefs.current.delete(s.id);
            }}
            className="framebuffer"
            style={{ display: s.id === activeId && !showForm ? "block" : "none" }}
            tabIndex={0}
            onMouseMove={(e) => sendPointer(e, s.id)}
            onMouseDown={(e) => sendPointer(e, s.id)}
            onMouseUp={(e) => sendPointer(e, s.id)}
            onWheel={(e) => onWheel(e, s.id)}
          />
        ))}
        {showForm && (
          <div className="lobby">
            <div className="connect-card">
              <h1 className="wordmark-large">Seance</h1>
              {connecting ? (
                <div className="connecting">
                  <div className="pulse" />
                  <p className="quip">{quip}</p>
                </div>
              ) : (
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    if (host) {
                      const pw = password;
                      setPassword("");
                      doConnect(host, port, username, pw, remember, group);
                    }
                  }}
                >
                  <label>
                    Host
                    <input
                      autoFocus
                      value={host}
                      onChange={(e) => setHost(e.target.value)}
                      placeholder="lab-vm-01 or 10.0.0.5"
                      spellCheck={false}
                    />
                  </label>
                  <div className="row">
                    <label className="grow">
                      Username
                      <input
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        placeholder="macOS hosts only"
                        spellCheck={false}
                        autoComplete="off"
                      />
                    </label>
                    <label className="port">
                      Port
                      <input
                        value={port}
                        onChange={(e) => setPort(e.target.value)}
                        inputMode="numeric"
                      />
                    </label>
                  </div>
                  <label>
                    Password
                    <input
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="optional"
                    />
                  </label>
                  <label>
                    Group
                    <input
                      value={group}
                      onChange={(e) => setGroup(e.target.value)}
                      placeholder="optional — e.g. Lab A"
                      list="known-groups"
                      spellCheck={false}
                    />
                  </label>
                  <datalist id="known-groups">
                    {groupNames.map((g) => (
                      <option key={g} value={g} />
                    ))}
                  </datalist>
                  <label className="remember">
                    <input
                      type="checkbox"
                      checked={remember}
                      onChange={(e) => setRemember(e.target.checked)}
                    />
                    Remember password (stored in the OS credential store)
                  </label>
                  <button
                    className="btn btn-primary btn-wide"
                    type="submit"
                    disabled={!host}
                  >
                    Connect
                  </button>
                  {sessions.length > 0 && (
                    <button type="button" className="btn btn-wide" onClick={cancelAdd}>
                      Cancel
                    </button>
                  )}
                  {error && <p className="error">{error}</p>}
                  {savedHosts.length > 0 && (
                    <div className="saved">
                      <button type="button" className="saved-header" onClick={toggleSaved}>
                        <span className={`saved-chevron ${savedOpen ? "open" : ""}`}>▸</span>
                        Saved ({savedHosts.length})
                      </button>
                      {savedOpen && (
                        <>
                          {savedHosts.some((s) => !s.group) && (
                            <div className="saved-chips">
                              {savedHosts
                                .filter((s) => !s.group)
                                .map((s) => chipFor(s))}
                            </div>
                          )}
                          {groupNames.map((g) => (
                            <div key={g} className="saved-group">
                              <button
                                type="button"
                                className="saved-header saved-group-header"
                                onClick={() => toggleGroup(g)}
                              >
                                <span
                                  className={`saved-chevron ${
                                    (groupsOpen[g] ?? true) ? "open" : ""
                                  }`}
                                >
                                  ▸
                                </span>
                                {g} ({savedHosts.filter((s) => s.group === g).length})
                              </button>
                              {(groupsOpen[g] ?? true) && (
                                <div className="saved-chips">
                                  {savedHosts
                                    .filter((s) => s.group === g)
                                    .map((s) => chipFor(s))}
                                </div>
                              )}
                            </div>
                          ))}
                        </>
                      )}
                    </div>
                  )}
                </form>
              )}
            </div>
          </div>
        )}
      </main>

      {pasteOpen && (
        <div className="modal-backdrop" onClick={() => setPasteOpen(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3>Type text on the remote</h3>
            <p className="modal-hint">
              Sent as individual keystrokes — works on login screens, password
              fields, anywhere.
            </p>
            <textarea
              autoFocus
              value={pasteText}
              onChange={(e) => setPasteText(e.target.value)}
              rows={4}
            />
            <div className="modal-actions">
              <button className="btn" onClick={() => setPasteOpen(false)}>
                Cancel
              </button>
              <button
                className="btn btn-primary"
                onClick={async () => {
                  setPasteOpen(false);
                  const id = activeIdRef.current;
                  if (pasteText && id != null) {
                    await invoke("type_text", { sessionId: id, text: pasteText }).catch(
                      (err) => setError(String(err)),
                    );
                    showToast(`Typed ${pasteText.length} characters`);
                  }
                }}
              >
                Type it
              </button>
            </div>
          </div>
        </div>
      )}
      {editing && (
        <div className="modal-backdrop" onClick={() => setEditing(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3>
              Edit {editing.host}:{editing.port}
            </h3>
            <label>
              Name
              <input
                autoFocus
                value={editName}
                onChange={(e) => setEditName(e.target.value)}
                spellCheck={false}
              />
            </label>
            <label>
              Group
              <input
                value={editGroup}
                onChange={(e) => setEditGroup(e.target.value)}
                placeholder="none — top level"
                list="known-groups"
                spellCheck={false}
                onKeyDown={(e) => {
                  if (e.key === "Enter") saveEdit();
                }}
              />
            </label>
            <div className="modal-actions">
              <button className="btn" onClick={() => setEditing(null)}>
                Cancel
              </button>
              <button className="btn btn-primary" onClick={saveEdit}>
                Save
              </button>
            </div>
          </div>
        </div>
      )}
      {dropped && (
        <div className="toast toast-action">
          <span>
            {dropped.name || dropped.host} disconnected — {dropped.reason}
          </span>
          <button className="btn btn-tiny btn-primary" onClick={reconnect}>
            Reconnect
          </button>
          <button className="btn btn-tiny" onClick={() => setDropped(null)}>
            Dismiss
          </button>
        </div>
      )}
      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}
