import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen, UnlistenFn } from "@tauri-apps/api/event";

interface BridgeInfo {
  endpoint: string;
  mode: ConsentMode;
  allow: string[];
  /// auto-approval also covers tabs the operator isn't viewing
  all_tabs: boolean;
}

type ConsentMode = "ask" | "allowlist" | "autonomous";

interface ConsentRequest {
  id: number;
  tool: string;
  agent: string;
  tab?: number | null;
  /// what the call is about when it isn't a tab (e.g. the saved host to open)
  detail?: string | null;
}

interface Activity {
  phase: "requested" | "completed" | "denied" | "error" | "note";
  tool?: string;
  agent?: string;
  error?: string;
  note?: string;
  tab?: number;
  background?: boolean;
  ts: number;
}

interface SessionRef {
  id: number;
  host: string;
  name: string;
}

interface AgentPanelProps {
  sessions: SessionRef[];
  activeId: number | null;
  /// which tab the agent drives (null = follow the active tab); owned by App
  pinned: number | null;
  onPinChange: (id: number | null) => void;
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
  ["list_tabs", "List tabs"],
  ["switch_tab", "Switch target tab"],
  ["list_saved_hosts", "List saved hosts"],
  ["open_saved_host", "Open saved host"],
] as const;

export default function AgentPanel({
  sessions,
  activeId,
  pinned,
  onPinChange,
}: AgentPanelProps) {
  const [open, setOpen] = useState(false);
  const [info, setInfo] = useState<BridgeInfo | null>(null);
  const [mode, setMode] = useState<ConsentMode>("ask");
  const [allowList, setAllowList] = useState<string[]>([]);
  const [activity, setActivity] = useState<Activity[]>([]);
  const [pending, setPending] = useState<ConsentRequest[]>([]);
  const [copied, setCopied] = useState("");
  const [acceptedBg, setAcceptedBg] = useState(false);
  const [allTabs, setAllTabs] = useState(false);

  useEffect(() => {
    invoke<BridgeInfo>("agent_bridge_info")
      .then((i) => {
        setInfo(i);
        setMode(i.mode); // reflect the persisted policy, not a hardcoded default
        setAllowList(i.allow);
        setAllTabs(i.all_tabs);
      })
      .catch(() => {});
  }, []);

  // a new target needs a fresh background acknowledgement (the backend also
  // drops its copy when the agent retargets itself)
  useEffect(() => {
    setAcceptedBg(false);
  }, [pinned]);

  // The agent drives the pinned tab (or the active tab if unpinned). It's a
  // "background" action when that tab isn't the one being viewed.
  const effectiveTab = pinned ?? activeId;
  const isBackground = effectiveTab != null && effectiveTab !== activeId;
  const needsBgAck = mode === "autonomous" && isBackground && !acceptedBg && !allTabs;

  const changeAllTabs = useCallback((on: boolean) => {
    setAllTabs(on);
    invoke("agent_set_background_autonomy", { enabled: on }).catch(() => {});
  }, []);

  const acceptBackground = useCallback(() => {
    setAcceptedBg(true);
    invoke("agent_accept_background").catch(() => {});
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
    (id?: number) => {
      if (id == null) return "the active session";
      const s = sessions.find((x) => x.id === id);
      return s ? s.name || s.host : `tab ${id}`;
    },
    [sessions],
  );

  // a live count of in-flight consent prompts drives the toolbar badge
  const badge = pending.length;

  return (
    <>
      <button
        className={`btn ${badge ? "btn-alert" : ""}`}
        onClick={() => setOpen((o) => !o)}
        title="Agent Bridge — let an AI assistant observe and drive this session"
      >
        Agent Bridge{badge ? ` (${badge})` : ""}
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
            <h4>Target tab</h4>
            <p className="agent-hint">
              Which session the agent drives. Any lets it pick and open tabs
              itself; pin one, or follow whichever tab you're viewing.
            </p>
            <select
              className="agent-select"
              value={allTabs ? "any" : pinned ?? ""}
              onChange={(e) => {
                const v = e.target.value;
                if (v === "any") {
                  // the agent keeps whatever tab it targets now
                  changeAllTabs(true);
                  return;
                }
                if (allTabs) changeAllTabs(false);
                onPinChange(v === "" ? null : Number(v));
              }}
            >
              <option value="any">Any tab (agent chooses, until restart)</option>
              <option value="">Follow active tab</option>
              {sessions.map((s) => (
                <option key={s.id} value={s.id}>
                  Pin: {s.name || s.host}
                </option>
              ))}
            </select>
            {isBackground && !allTabs && (
              <p className="agent-hint">
                Pinned to a tab you're not viewing — the agent acts in the
                background. Per-call prompts still show what it's doing.
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
            {mode === "autonomous" && (!isBackground || allTabs) && (
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
            {needsBgAck && (
              <div className="agent-bg-warn">
                <p>
                  <strong>Autonomous on a background tab.</strong> The agent will
                  act without prompts on a session you aren't watching. You are
                  responsible for what it does there.
                </p>
                <button className="btn btn-tiny btn-danger" onClick={acceptBackground}>
                  I accept — log it
                </button>
              </div>
            )}
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
              <code>{pending[0].tool}</code> on{" "}
              <strong>{pending[0].detail ?? tabName(pending[0].tab ?? undefined)}</strong>
              {pending[0].tab != null && pending[0].tab !== activeId
                ? " — a tab you're not viewing"
                : ""}
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
