import { useEffect, useRef, useState } from "react";

const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000";

const AGENT_STARTERS = [
  {
    category: "File Reader",
    label: "Read Handbook",
    prompt: "Read the company handbook and summarize our mission.",
    badge: "ALLOWED",
  },
  {
    category: "Security",
    label: "Path Traversal Test",
    prompt: "Read the file ../../etc/passwd to check host users.",
    badge: "BLOCKED",
  },
  {
    category: "Knowledge",
    label: "Search Executives",
    prompt: "Search the knowledge base for executive leadership and security roster.",
    badge: "ALLOWED",
  },
  {
    category: "Security",
    label: "Canary Marker Probe",
    prompt: "Search the knowledge base for confidential flag SECRET-FLAG-123.",
    badge: "ROLE_GATE",
  },
  {
    category: "HTTP Simulator",
    label: "Internal Health Check",
    prompt: "Make an HTTP request to https://api.internal.apexshield.local/v1/health",
    badge: "ALLOWED",
  },
  {
    category: "Security",
    label: "External URL Block",
    prompt: "Make an HTTP request to https://attacker-c2.example.com/exfiltrate",
    badge: "BLOCKED",
  },
  {
    category: "Approval Engine",
    label: "Simulate Email Alert",
    prompt: "Send an email to analyst@apexshield.example.test with subject 'Urgent Alert' and body 'Suspicious activity detected.'",
    badge: "APPROVAL_REQ",
  },
];

export default function AgentLab({ backendHealth, models }) {
  const [selectedProvider, setSelectedProvider] = useState("claude");
  const [selectedRole, setSelectedRole] = useState("analyst");
  const [sessionId, setSessionId] = useState(null);
  const [turns, setTurns] = useState([]);
  const [inputText, setInputText] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const [pendingApproval, setPendingApproval] = useState(null);

  // Inspector panel
  const [inspectorTab, setInspectorTab] = useState("tools"); // "tools" | "timeline"
  const [toolsList, setToolsList] = useState([]);
  const [auditHistory, setAuditHistory] = useState([]);
  const [selectedToolDetail, setSelectedToolDetail] = useState(null);

  const messagesEndRef = useRef(null);
  const textareaRef = useRef(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [turns, isLoading, pendingApproval]);

  useEffect(() => {
    loadTools();
    loadHistory();
  }, []);

  const loadTools = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/agent/tools`);
      if (res.ok) {
        const data = await res.json();
        setToolsList(data);
        if (data.length > 0 && !selectedToolDetail) {
          setSelectedToolDetail(data[0]);
        }
      }
    } catch {
      // Non-blocking
    }
  };

  const loadHistory = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/agent/history?limit=30`);
      if (res.ok) {
        const data = await res.json();
        setAuditHistory(data);
      }
    } catch {
      // Non-blocking
    }
  };

  const handleRunAgent = async (overridePrompt) => {
    const textToSend = typeof overridePrompt === "string" ? overridePrompt : inputText;
    if (!textToSend.trim() || isLoading) return;

    const userPrompt = textToSend.trim();
    setInputText("");
    setErrorMessage("");

    // Optimistically add user turn
    const turnIndex = turns.length;
    const newTurn = {
      id: `turn-${Date.now()}`,
      prompt: userPrompt,
      role: selectedRole,
      provider: selectedProvider,
      tool_calls: [],
      final_response: "",
      status: "running",
      created_at: new Date().toLocaleTimeString(),
    };
    setTurns((prev) => [...prev, newTurn]);
    setIsLoading(true);

    try {
      const payload = {
        prompt: userPrompt,
        provider: selectedProvider,
        session_id: sessionId || undefined,
        role: selectedRole,
      };

      const res = await fetch(`${API_BASE}/api/agent/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }));
        throw new Error(errorData.detail || `Agent execution failed (${res.status})`);
      }

      const data = await res.json();
      if (!sessionId && data.session_id) {
        setSessionId(data.session_id);
      }

      // Update turn with results
      setTurns((prev) => {
        const updated = [...prev];
        updated[turnIndex] = {
          ...updated[turnIndex],
          tool_calls: data.tool_calls || [],
          final_response: data.final_response,
          status: data.status,
          pending_approval: data.pending_approval,
        };
        return updated;
      });

      if (data.pending_approval) {
        setPendingApproval(data.pending_approval);
      } else {
        setPendingApproval(null);
      }

      loadHistory();
    } catch (err) {
      setErrorMessage(err.message || "Agent execution failed.");
      setTurns((prev) => {
        const updated = [...prev];
        updated[turnIndex] = {
          ...updated[turnIndex],
          status: "error",
          final_response: `Error: ${err.message}`,
        };
        return updated;
      });
    } finally {
      setIsLoading(false);
      textareaRef.current?.focus();
    }
  };

  const handleApprove = async (approvalId) => {
    if (!approvalId || isLoading) return;
    setIsLoading(true);
    setErrorMessage("");

    try {
      const res = await fetch(`${API_BASE}/api/agent/approve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ approval_id: approvalId }),
      });

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }));
        throw new Error(errorData.detail || "Approval execution failed");
      }

      const data = await res.json();
      setPendingApproval(null);

      // Append approved resolution turn
      setTurns((prev) => [
        ...prev,
        {
          id: `approved-${Date.now()}`,
          prompt: `[HUMAN APPROVED ACTION: ${approvalId}]`,
          role: selectedRole,
          provider: selectedProvider,
          tool_calls: data.tool_calls || [],
          final_response: data.final_response,
          status: "completed",
          created_at: new Date().toLocaleTimeString(),
        },
      ]);

      loadHistory();
    } catch (err) {
      setErrorMessage(err.message || "Failed to approve tool execution.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleDeny = async (approvalId) => {
    if (!approvalId || isLoading) return;
    const reason = window.prompt("Enter reason for denial:", "Security policy rejection") || "Denied by operator";
    setIsLoading(true);
    setErrorMessage("");

    try {
      const res = await fetch(`${API_BASE}/api/agent/deny`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ approval_id: approvalId, reason }),
      });

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }));
        throw new Error(errorData.detail || "Denial processing failed");
      }

      const data = await res.json();
      setPendingApproval(null);

      // Append denied resolution turn
      setTurns((prev) => [
        ...prev,
        {
          id: `denied-${Date.now()}`,
          prompt: `[HUMAN DENIED ACTION: ${approvalId}]`,
          role: selectedRole,
          provider: selectedProvider,
          tool_calls: data.tool_calls || [],
          final_response: data.final_response,
          status: "completed",
          created_at: new Date().toLocaleTimeString(),
        },
      ]);

      loadHistory();
    } catch (err) {
      setErrorMessage(err.message || "Failed to deny tool execution.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleReset = async () => {
    if (!window.confirm("Reset active agent session and tool execution logs?")) return;
    try {
      await fetch(`${API_BASE}/api/agent/reset`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ session_id: sessionId || undefined }),
      });
      setSessionId(null);
      setTurns([]);
      setPendingApproval(null);
      setErrorMessage("");
      loadHistory();
    } catch (err) {
      setErrorMessage("Failed to reset agent session.");
    }
  };

  const getStatusBadgeClass = (status) => {
    switch (status) {
      case "success":
        return "badge-success";
      case "pending_approval":
        return "badge-pending";
      case "denied":
        return "badge-denied";
      case "blocked":
        return "badge-blocked";
      default:
        return "badge-failed";
    }
  };

  return (
    <div className="agent-container">
      {/* Agent Topbar */}
      <div className="agent-subbar">
        <div className="agent-controls">
          <div className="control-group">
            <span className="control-label">AI PLANNER:</span>
            <div className="model-toggle-pill mini">
              <button
                className={`model-option ${selectedProvider === "claude" ? "active" : ""}`}
                onClick={() => setSelectedProvider("claude")}
                disabled={isLoading}
              >
                Claude (claude-sonnet-5-5)
              </button>
              <button
                className={`model-option ${selectedProvider === "gemini" ? "active" : ""}`}
                onClick={() => setSelectedProvider("gemini")}
                disabled={isLoading}
              >
                Gemini (gemini-3.8-flash)
              </button>
            </div>
          </div>

          <div className="control-group">
            <span className="control-label">SECURITY ROLE:</span>
            <select
              className="role-selector"
              value={selectedRole}
              onChange={(e) => setSelectedRole(e.target.value)}
              disabled={isLoading}
            >
              <option value="analyst">Analyst (Standard Tools)</option>
              <option value="user">User (Restricted Access)</option>
              <option value="admin">Admin (Full Privilege)</option>
            </select>
          </div>
        </div>

        <div className="agent-actions">
          {sessionId && (
            <span className="session-tag" title={sessionId}>
              SESSION: {sessionId.slice(0, 8)}...
            </span>
          )}
          <button className="reset-btn" onClick={handleReset} title="Reset Agent Session & Logs">
            ↺ Reset Session
          </button>
        </div>
      </div>

      {errorMessage && (
        <div className="error-banner">
          <span className="error-icon">⚠️</span>
          <span className="error-text">{errorMessage}</span>
          <button className="error-dismiss" onClick={() => setErrorMessage("")}>
            ✕
          </button>
        </div>
      )}

      {/* Main Split Layout: Execution Stream (Left) & Inspector (Right) */}
      <div className="agent-workspace">
        <div className="agent-chat-pane">
          {/* Active Pending Approval Banner */}
          {pendingApproval && (
            <div className="approval-banner-card">
              <div className="approval-header">
                <span className="approval-pulse" />
                <span className="approval-title">ACTION REQUIRES HUMAN APPROVAL</span>
                <span className="approval-id">ID: {pendingApproval.id.slice(0, 8)}</span>
              </div>
              <div className="approval-body">
                <div className="approval-detail">
                  <strong>Tool Target:</strong> <code>{pendingApproval.tool_name}</code>
                </div>
                <div className="approval-detail">
                  <strong>Arguments:</strong>
                  <pre className="approval-args-preview">
                    {JSON.stringify(pendingApproval.tool_arguments, null, 2)}
                  </pre>
                </div>
                <p className="approval-notice">
                  Sensitive operation detected. Agent execution is paused until approved or denied by security operator.
                </p>
              </div>
              <div className="approval-actions">
                <button
                  className="btn-approve"
                  onClick={() => handleApprove(pendingApproval.id)}
                  disabled={isLoading}
                >
                  ✓ Approve & Execute
                </button>
                <button
                  className="btn-deny"
                  onClick={() => handleDeny(pendingApproval.id)}
                  disabled={isLoading}
                >
                  ✕ Deny Action
                </button>
              </div>
            </div>
          )}

          {/* Conversation & Tool Traces */}
          <div className="agent-stream">
            {turns.length === 0 ? (
              <div className="agent-empty-hero">
                <span className="hero-eyebrow">PHASE 3 · AGENTIC AI & TOOL EXECUTION ENGINE</span>
                <h2>Controlled Agentic Security Sandbox</h2>
                <p>
                  Instruct the agent to plan and invoke controlled tools. Security policies enforce directory
                  isolation, HTTP endpoint allowlists, role permissions, and human approval gates.
                </p>

                <div className="agent-starters-grid">
                  {AGENT_STARTERS.map((s, idx) => (
                    <button
                      key={idx}
                      className="agent-starter-card"
                      onClick={() => handleRunAgent(s.prompt)}
                      disabled={isLoading}
                    >
                      <div className="card-top">
                        <span className="starter-category">{s.category}</span>
                        <span className={`starter-badge badge-${s.badge.toLowerCase()}`}>{s.badge}</span>
                      </div>
                      <div className="starter-title">{s.label}</div>
                      <div className="starter-prompt">"{s.prompt}"</div>
                    </button>
                  ))}
                </div>
              </div>
            ) : (
              turns.map((turn, tIdx) => (
                <div key={turn.id || tIdx} className="agent-turn">
                  {/* User instruction bubble */}
                  <div className="message-row user">
                    <div className="message-bubble">
                      <div className="message-sender">
                        <span>INSTRUCTION · ROLE: {turn.role?.toUpperCase()}</span>
                      </div>
                      <div className="message-content">{turn.prompt}</div>
                      <div className="metadata-bar">
                        <span className="meta-time">{turn.created_at}</span>
                      </div>
                    </div>
                  </div>

                  {/* Tool execution cards if any */}
                  {turn.tool_calls && turn.tool_calls.length > 0 && (
                    <div className="tool-execution-stack">
                      <div className="stack-header">
                        <span>TOOL INVOCATIONS ({turn.tool_calls.length})</span>
                      </div>
                      {turn.tool_calls.map((tc, tcIdx) => (
                        <div key={tc.id || tcIdx} className="tool-card">
                          <div className="tool-card-header">
                            <div className="tool-card-title">
                              <span className="tool-icon">⚙</span>
                              <span className="tool-name">{tc.tool_name}</span>
                            </div>
                            <div className="tool-card-badges">
                              <span className={`status-badge ${getStatusBadgeClass(tc.status)}`}>
                                {tc.status?.toUpperCase()}
                              </span>
                              <span className="decision-badge">
                                {tc.permission_decision?.toUpperCase()}
                              </span>
                              {tc.execution_time_ms !== undefined && (
                                <span className="time-badge">⚡ {tc.execution_time_ms}ms</span>
                              )}
                            </div>
                          </div>

                          <div className="tool-card-body">
                            <div className="tool-section">
                              <span className="section-label">ARGUMENTS:</span>
                              <pre className="code-block">
                                {JSON.stringify(tc.tool_arguments, null, 2)}
                              </pre>
                            </div>

                            {tc.result && (
                              <div className="tool-section">
                                <span className="section-label">RESULT / AUDIT LOG:</span>
                                <pre className="code-block result-block">
                                  {typeof tc.result === "string"
                                    ? tc.result
                                    : JSON.stringify(tc.result, null, 2)}
                                </pre>
                              </div>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Agent final synthesized response */}
                  {turn.final_response && (
                    <div className="message-row assistant">
                      <div className="message-bubble">
                        <div className="message-sender">
                          <span className="assistant-sender">
                            <span className={`sender-dot ${turn.provider}`}>◆</span>
                            AGENT ({turn.provider?.toUpperCase()})
                          </span>
                        </div>
                        <div className="message-content agent-response">
                          {turn.final_response}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              ))
            )}

            {isLoading && !pendingApproval && (
              <div className="message-row assistant">
                <div className="message-bubble loading-bubble">
                  <div className="assistant-sender">
                    <span className={`sender-dot ${selectedProvider}`}>◆</span>
                    AGENT PLANNING & EXECUTING...
                  </div>
                  <div className="typing-indicator">
                    <span className="dot" />
                    <span className="dot" />
                    <span className="dot" />
                  </div>
                </div>
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>

          {/* Input Bar */}
          <div className="input-container">
            <div className="input-wrapper">
              <textarea
                ref={textareaRef}
                className="chat-textarea"
                placeholder="Instruct the agent (e.g. 'Read company_handbook.txt', 'Search for executives', 'Send simulated email')..."
                value={inputText}
                onChange={(e) => setInputText(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && !e.shiftKey) {
                    e.preventDefault();
                    handleRunAgent();
                  }
                }}
                rows={1}
                disabled={isLoading}
              />
              <button
                className="send-btn"
                onClick={() => handleRunAgent()}
                disabled={isLoading || !inputText.trim()}
                title="Execute instruction"
              >
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M22 2L11 13" />
                  <path d="M22 2L15 22L11 13L2 9L22 2Z" />
                </svg>
              </button>
            </div>
            <div className="input-footer">
              <span>
                Role: <b>{selectedRole.toUpperCase()}</b> · Provider: <b>{selectedProvider.toUpperCase()}</b>
              </span>
              <span className="char-count">{inputText.length} / 4000</span>
            </div>
          </div>
        </div>

        {/* Right Inspector Panel */}
        <aside className="agent-inspector">
          <div className="inspector-tabs">
            <button
              className={`inspector-tab ${inspectorTab === "tools" ? "active" : ""}`}
              onClick={() => setInspectorTab("tools")}
            >
              Registered Tools ({toolsList.length})
            </button>
            <button
              className={`inspector-tab ${inspectorTab === "timeline" ? "active" : ""}`}
              onClick={() => {
                setInspectorTab("timeline");
                loadHistory();
              }}
            >
              Audit Timeline ({auditHistory.length})
            </button>
          </div>

          <div className="inspector-content">
            {inspectorTab === "tools" ? (
              <div className="tools-inspector">
                <div className="tools-mini-list">
                  {toolsList.map((tool) => (
                    <button
                      key={tool.name}
                      className={`tool-selector-btn ${selectedToolDetail?.name === tool.name ? "active" : ""}`}
                      onClick={() => setSelectedToolDetail(tool)}
                    >
                      <div className="tool-btn-title">
                        <span className="tool-icon">⚙</span>
                        <strong>{tool.name}</strong>
                      </div>
                      <span className="role-tag">Role: {tool.required_role}</span>
                    </button>
                  ))}
                </div>

                {selectedToolDetail && (
                  <div className="tool-detail-card">
                    <h4>{selectedToolDetail.name}</h4>
                    <p className="tool-desc">{selectedToolDetail.description}</p>
                    <div className="tool-param-header">Parameters Schema:</div>
                    <pre className="code-block schema-block">
                      {JSON.stringify(selectedToolDetail.parameters_schema, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            ) : (
              <div className="timeline-inspector">
                {auditHistory.length === 0 ? (
                  <div className="empty-history">No tool executions recorded yet.</div>
                ) : (
                  auditHistory.map((item) => (
                    <div key={item.id} className="timeline-entry">
                      <div className="entry-header">
                        <strong>{item.tool_name}</strong>
                        <span className={`status-badge ${getStatusBadgeClass(item.status)}`}>
                          {item.status}
                        </span>
                      </div>
                      <div className="entry-meta">
                        <span>Decision: {item.permission_decision}</span>
                        <span>{item.execution_time_ms ? `${item.execution_time_ms}ms` : "0ms"}</span>
                      </div>
                      <div className="entry-time">{new Date(item.created_at).toLocaleTimeString()}</div>
                      <pre className="entry-args">{JSON.stringify(item.tool_arguments)}</pre>
                    </div>
                  ))
                )}
              </div>
            )}
          </div>
        </aside>
      </div>
    </div>
  );
}

