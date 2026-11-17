import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen, UnlistenFn } from "@tauri-apps/api/event";

interface BridgeInfo {
  endpoint: string;
  mode: ConsentMode;
  allow: string[];
}

type ConsentMode = "ask" | "allowlist" | "autonomous";

interface ConsentRequest {
  id: number;
  tool: string;
  agent: string;
  tab?: number | null;
}

interface Activity {
  phase: "requested" | "completed" | "denied" | "error" | "note";
  tool?: string;
  agent?: string;
  error?: string;
  note?: string;
  tab?: number | null;
  background?: boolean;
  ts: number;
}

interface ShareState {
  pinned: number[];
  acks: { tab: number; expires: number }[];
}

interface SessionRef {
  id: number;
  host: string;
  name: string;
}

interface AgentPanelProps {
  sessions: SessionRef[];
  activeId: number | null;
}

// keep the feed bounded — this is a live view, not the audit log
const MAX_ACTIVITY = 200;
const AGENT_TOOLS = [
  ["screenshot", "Screenshot"],
  ["type_text", "Type text"],
  ["key_combo", "Key combo"],
  ["move_pointer", "Move pointer"],
  ["click", "Click"],
  ["scroll", "Scroll"],
  ["get_clipboard", "Get clipboard"],
  ["set_clipboard", "Set clipboard"],
  ["list_targets", "List targets"],
] as const;

export default function AgentPanel({ sessions, activeId }: AgentPanelProps) {
  const [open, setOpen] = useState(false);
  const [info, setInfo] = useState<BridgeInfo | null>(null);
  const [mode, setMode] = useState<ConsentMode>("ask");
  const [allowList, setAllowList] = useState<string[]>([]);
  const [activity, setActivity] = useState<Activity[]>([]);
  const [pending, setPending] = useState<ConsentRequest[]>([]);
  const [copied, setCopied] = useState("");
  // tabs shared with agents (empty = follow the active tab)
  const [pinned, setPinned] = useState<number[]>([]);
  // tab -> when its background acknowledgement expires (epoch ms)
  const [acceptedBg, setAcceptedBg] = useState<Record<number, number>>({});
  const [now, setNow] = useState(() => Date.now());
  const [shareError, setShareError] = useState("");

  const sharePins = useCallback((ids: number[]) => {
    invoke("set_pinned", { ids })
      .then(() => setShareError(""))
      .catch((e) => setShareError(String(e)));
  }, []);

  useEffect(() => {
    invoke<BridgeInfo>("agent_bridge_info")
      .then((i) => {
        setInfo(i);
        setMode(i.mode); // reflect the persisted policy, not a hardcoded default
        setAllowList(i.allow);
      })
      .catch(() => {});
    invoke<ShareState>("agent_share_state")
      .then((s) => {
        setPinned(s.pinned);
        setAcceptedBg(Object.fromEntries(s.acks.map((a) => [a.tab, a.expires])));
      })
      .catch(() => {});
    const tick = window.setInterval(() => setNow(Date.now()), 60_000);
    return () => window.clearInterval(tick);
  }, []);

  // drop pins whose tabs closed
  useEffect(() => {
    const live = pinned.filter((id) => sessions.some((s) => s.id === id));
    if (live.length !== pinned.length) {
      setPinned(live);
      sharePins(live);
    }
  }, [sessions, pinned, sharePins]);

  const togglePin = useCallback(
    (id: number) => {
      setPinned((cur) => {
        const next = cur.includes(id) ? cur.filter((t) => t !== id) : [...cur, id];
        sharePins(next);
        return next;
      });
      setAcceptedBg((cur) => {
        const next = { ...cur };
        delete next[id];
        return next;
      });
    },
    [sharePins],
  );

  // Agents drive the shared tabs (or the active tab if none is shared). It's
  // a "background" action on a shared tab that isn't the one being viewed.
  const bgTabs = pinned.filter((id) => id !== activeId);
  const isBackground = bgTabs.length > 0;
  // With several tabs shared, switching your view puts any of them in the
  // background, so all of them can be accepted up front.
  const ackTabs = mode === "ask" ? [] : pinned.length > 1 ? pinned : bgTabs;
  const isAccepted = (id: number) => (acceptedBg[id] ?? 0) > now;
  const needsBgAck = ackTabs.filter((id) => !isAccepted(id));
  const acceptedTabs = ackTabs.filter(isAccepted);

  const acceptBackground = useCallback((tab: number) => {
    invoke<number>("agent_accept_background", { tab })
      .then((expires) => setAcceptedBg((cur) => ({ ...cur, [tab]: expires })))
      .catch(() => {});
  }, []);

  useEffect(() => {
    const subs: Promise<UnlistenFn>[] = [
      listen<Activity>("agent-activity", (e) => {
        setActivity((a) => [e.payload, ...a].slice(0, MAX_ACTIVITY));
      }),
      listen<ConsentRequest>("agent-consent-request", (e) => {
        setPending((p) => [...p, e.payload]);
      }),
    ];
    return () => subs.forEach((s) => s.then((f) => f()));
  }, []);

  const respond = useCallback((id: number, approved: boolean) => {
    invoke("agent_consent_respond", { id, approved }).catch(() => {});
    setPending((p) => p.filter((r) => r.id !== id));
  }, []);

  const changeMode = useCallback((m: ConsentMode) => {
    setMode(m);
    invoke("agent_set_consent", { mode: m, allow: allowList }).catch(() => {});
  }, [allowList]);

  const markCopied = useCallback((label: string) => {
    setCopied(label);
    window.setTimeout(() => setCopied(""), 1500);
  }, []);

  const copyViaRust = useCallback(
    (label: string, command: string) => {
      invoke(command)
        .then(() => markCopied(label))
        .catch(() => {});
    },
    [markCopied],
  );

  const toggleAllow = useCallback(
    (tool: string) => {
      setAllowList((cur) => {
        const next = cur.includes(tool) ? cur.filter((t) => t !== tool) : [...cur, tool];
        invoke("agent_set_consent", { mode, allow: next }).catch(() => {});
        return next;
      });
    },
    [mode],
  );

  const tabName = useCallback(
    (id?: number | null) => {
      if (id == null) return "the active session";
      const s = sessions.find((x) => x.id === id);
      return s ? s.name || s.host : `tab ${id}`;
    },
    [sessions],
  );

  // a live count of in-flight consent prompts drives the toolbar badge
  const badge = pending.length;
  const attention = badge > 0 || needsBgAck.length > 0;

  return (
    <>
      <button
        className={`btn ${attention ? "btn-alert" : ""}`}
        onClick={() => setOpen((o) => !o)}
        title="Agent Bridge — let an AI assistant observe and drive this session"
      >
        Agent Bridge{badge ? ` (${badge})` : needsBgAck.length ? " (!)" : ""}
      </button>

      {open && (
        <div className="agent-panel">
          <div className="agent-section">
            <h4>Connect an assistant</h4>
            <p className="agent-hint">
              A local, token-gated MCP endpoint. Point any MCP client at it; every
              tool call is gated by the consent policy below and recorded to the
              audit log.
            </p>
            <div className="agent-field">
              <span className="agent-label">Endpoint</span>
              <code>{info?.endpoint ?? "…"}</code>
              <button
                className="btn btn-tiny"
                onClick={() => copyViaRust("endpoint", "agent_copy_endpoint")}
                disabled={!info}
              >
                {copied === "endpoint" ? "Copied" : "Copy"}
              </button>
            </div>
            <div className="agent-field">
              <span className="agent-label">Token</span>
              <code>{info ? "•".repeat(16) : "…"}</code>
              <button
                className="btn btn-tiny"
                onClick={() => copyViaRust("token", "agent_copy_bridge_token")}
                disabled={!info}
              >
                {copied === "token" ? "Copied" : "Copy"}
              </button>
              <button
                className="btn btn-tiny"
                title="Mint a new token — connected agents must re-register"
                onClick={() =>
                  invoke("agent_rotate_token").then(() => markCopied("rotated"))
                }
              >
                {copied === "rotated" ? "Rotated" : "Rotate"}
              </button>
            </div>
            <p className="agent-hint">
              The endpoint and token are stable across restarts (token lives in
              the OS credential store) — register your agent once. Rotate to
              revoke all existing registrations.
            </p>
            <div className="agent-field">
              <span className="agent-label">Claude Code</span>
              <button
                className="btn btn-tiny"
                onClick={() => copyViaRust("cmd", "agent_copy_add_command")}
                disabled={!info}
              >
                {copied === "cmd" ? "Copied command" : "Copy add command"}
              </button>
            </div>
          </div>

          <div className="agent-section">
            <h4>Shared with agents</h4>
            <p className="agent-hint">
              Tabs an agent may drive. With none checked, it follows the tab
              you're viewing. With several, each call must name its target.
            </p>
            {sessions.length === 0 ? (
              <p className="agent-hint">No open sessions.</p>
            ) : (
              <div className="allow-tools">
                {sessions.map((s) => (
                  <label key={s.id} className="allow-tool">
                    <input
                      type="checkbox"
                      checked={pinned.includes(s.id)}
                      onChange={() => togglePin(s.id)}
                    />
                    {s.name || s.host}
                    <span className="share-tab-id">#{s.id}</span>
                  </label>
                ))}
              </div>
            )}
            {shareError && <p className="agent-warn">Sharing failed: {shareError}</p>}
            {isBackground && (
              <p className="agent-hint">
                Shared tabs you're not viewing are driven in the background.
                Per-call prompts still show what the agent is doing.
              </p>
            )}
          </div>

          <div className="agent-section">
            <h4>Consent policy</h4>
            <div className="agent-modes">
              {(["ask", "allowlist", "autonomous"] as ConsentMode[]).map((m) => (
                <label key={m} className={mode === m ? "active" : ""}>
                  <input
                    type="radio"
                    name="consent"
                    checked={mode === m}
                    onChange={() => changeMode(m)}
                  />
                  {m === "ask"
                    ? "Ask every call"
                    : m === "allowlist"
                    ? "Allow-list"
                    : "Autonomous"}
                </label>
              ))}
            </div>
            {mode === "autonomous" && !isBackground && (
              <p className="agent-warn">
                Every tool call runs without asking. Watch the activity feed.
              </p>
            )}
            {mode === "allowlist" && (
              <div className="allow-tools">
                {AGENT_TOOLS.map(([tool, label]) => (
                  <label key={tool} className="allow-tool">
                    <input
                      type="checkbox"
                      checked={allowList.includes(tool)}
                      onChange={() => toggleAllow(tool)}
                    />
                    {label}
                  </label>
                ))}
              </div>
            )}
            {needsBgAck.map((id) => (
              <div key={id} className="agent-bg-warn">
                <p>
                  <strong>Unattended actions on {tabName(id)}.</strong> Once you
                  accept, agents act there without prompts whenever you aren't
                  watching it, for 24 hours. You are responsible for what they
                  do there.
                </p>
                <button
                  className="btn btn-tiny btn-danger"
                  onClick={() => acceptBackground(id)}
                >
                  I accept, log it
                </button>
              </div>
            ))}
            {acceptedTabs.map((id) => (
              <p key={id} className="agent-hint">
                Unattended actions accepted on {tabName(id)} until{" "}
                {new Date(acceptedBg[id]).toLocaleString([], {
                  weekday: "short",
                  hour: "2-digit",
                  minute: "2-digit",
                })}
                .
              </p>
            ))}
          </div>

          <div className="agent-section agent-feed">
            <h4>Activity</h4>
            {activity.length === 0 ? (
              <p className="agent-hint">No calls yet.</p>
            ) : (
              <ul>
                {activity.map((a, i) =>
                  a.phase === "note" ? (
                    <li key={i} className="act act-note">
                      {a.note}
                    </li>
                  ) : (
                    <li key={i} className={`act act-${a.phase}`}>
                      <span className="act-tool">{a.tool}</span>
                      {a.tab != null && <span className="act-target">{tabName(a.tab)}</span>}
                      {a.agent && <span className="act-target">{a.agent}</span>}
                      {a.background && <span className="act-bg">bg</span>}
                      <span className="act-phase">{a.phase}</span>
                      {a.error && <span className="act-error">{a.error}</span>}
                    </li>
                  ),
                )}
              </ul>
            )}
          </div>
        </div>
      )}

      {pending.length > 0 && (
        <div className="modal-backdrop">
          <div className="modal consent-modal" onClick={(e) => e.stopPropagation()}>
            <h3>Allow agent action?</h3>
            <p className="modal-hint">
              <strong>{pending[0].agent}</strong> wants to call{" "}
              <code>{pending[0].tool}</code>
              {pending[0].tab != null && (
                <>
                  {" "}on <strong>{tabName(pending[0].tab)}</strong>
                  {pending[0].tab !== activeId ? ", a tab you're not viewing" : ""}
                </>
              )}
              .
            </p>
            <div className="modal-actions">
              <button className="btn btn-danger" onClick={() => respond(pending[0].id, false)}>
                Deny
              </button>
              <button className="btn btn-primary" onClick={() => respond(pending[0].id, true)}>
                Allow
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
