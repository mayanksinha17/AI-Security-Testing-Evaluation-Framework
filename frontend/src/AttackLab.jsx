import { useEffect, useState } from "react";

const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000";

export default function AttackLab({ backendHealth, models }) {
  // Config & State
  const [selectedProvider, setSelectedProvider] = useState("claude");
  const [selectedStage, setSelectedStage] = useState("BASELINE"); // "BASELINE" | "POST_MITIGATION"
  const [selectedRole, setSelectedRole] = useState("analyst");
  const [activeRiskFilter, setActiveRiskFilter] = useState("ALL");

  // Data
  const [risks, setRisks] = useState([]);
  const [scenarios, setScenarios] = useState([]);
  const [resultsMap, setResultsMap] = useState({}); // scenario_id -> latest result
  const [summary, setSummary] = useState(null);
  const [historyRuns, setHistoryRuns] = useState([]);

  // UI state
  const [isRunningAll, setIsRunningAll] = useState(false);
  const [runningScenarioId, setRunningScenarioId] = useState(null);
  const [selectedResultModal, setSelectedResultModal] = useState(null);
  const [errorMessage, setErrorMessage] = useState("");
  const [activeViewTab, setActiveViewTab] = useState("scenarios"); // "scenarios" | "summary"

  useEffect(() => {
    loadInitialData();
  }, []);

  useEffect(() => {
    loadResults();
  }, [selectedStage, selectedProvider]);

  const loadInitialData = async () => {
    try {
      const [risksRes, scenariosRes, summaryRes] = await Promise.all([
        fetch(`${API_BASE}/api/attacks/risks`),
        fetch(`${API_BASE}/api/attacks/scenarios`),
        fetch(`${API_BASE}/api/attacks/summary`),
      ]);

      if (risksRes.ok) {
        const data = await risksRes.json();
        setRisks(data);
      }
      if (scenariosRes.ok) {
        const data = await scenariosRes.json();
        setScenarios(data);
      }
      if (summaryRes.ok) {
        const data = await summaryRes.json();
        setSummary(data);
      }
    } catch {
      setErrorMessage("Failed to load attack testing metadata from API.");
    }
  };

  const loadResults = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/attacks/results?limit=100&stage=${selectedStage}&provider=${selectedProvider}`);
      if (res.ok) {
        const data = await res.json();
        const map = {};
        for (const r of data) {
          if (!map[r.scenario_id]) {
            map[r.scenario_id] = r;
          }
        }
        setResultsMap(map);
      }
    } catch {
      // Non-blocking
    }
  };

  const refreshSummary = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/attacks/summary`);
      if (res.ok) {
        const data = await res.json();
        setSummary(data);
      }
      await loadResults();
    } catch {
      // Non-blocking
    }
  };

  const handleRunSingle = async (scenarioId) => {
    if (runningScenarioId || isRunningAll) return;
    setRunningScenarioId(scenarioId);
    setErrorMessage("");

    try {
      const payload = {
        scenario_id: scenarioId,
        provider: selectedProvider,
        stage: selectedStage,
        role: selectedRole,
      };

      const res = await fetch(`${API_BASE}/api/attacks/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }));
        throw new Error(err.detail || "Attack execution failed");
      }

      const result = await res.json();
      setResultsMap((prev) => ({ ...prev, [scenarioId]: result }));
      refreshSummary();
    } catch (err) {
      setErrorMessage(err.message || "Failed to execute attack scenario.");
    } finally {
      setRunningScenarioId(null);
    }
  };

  const handleRunBatch = async (riskIdFilter = null) => {
    if (isRunningAll || runningScenarioId) return;
    setIsRunningAll(true);
    setErrorMessage("");

    try {
      const payload = {
        risk_id: riskIdFilter || (activeRiskFilter !== "ALL" ? activeRiskFilter : null),
        provider: selectedProvider,
        stage: selectedStage,
        role: selectedRole,
      };

      const res = await fetch(`${API_BASE}/api/attacks/run-batch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }));
        throw new Error(err.detail || "Batch attack execution failed");
      }

      const runResponse = await res.json();
      // Update results in map
      const newMap = { ...resultsMap };
      for (const r of runResponse.results || []) {
        newMap[r.scenario_id] = r;
      }
      setResultsMap(newMap);
      refreshSummary();
    } catch (err) {
      setErrorMessage(err.message || "Failed to execute batch attack.");
    } finally {
      setIsRunningAll(false);
    }
  };

  const filteredScenarios = activeRiskFilter === "ALL"
    ? scenarios
    : scenarios.filter((s) => s.risk_id === activeRiskFilter);

  const getResultBadge = (scenarioId) => {
    const res = resultsMap[scenarioId];
    if (!res) {
      return <span className="status-badge badge-not-run">⚪ NOT_RUN</span>;
    }

    switch (res.result_classification) {
      case "BLOCKED":
        return <span className="status-badge badge-success">🛡️ BLOCKED</span>;
      case "PARTIAL":
        return <span className="status-badge badge-pending">⚠️ PARTIAL</span>;
      case "SUCCEEDED":
        return <span className="status-badge badge-denied">❌ SUCCEEDED</span>;
      case "ERROR":
        return <span className="status-badge badge-blocked">⚠️ ERROR</span>;
      default:
        return <span className="status-badge badge-not-run">⚪ NOT_RUN</span>;
    }
  };

  // Compute stats for current view
  const currentStageStats = selectedStage === "BASELINE"
    ? summary?.baseline_stats
    : summary?.post_mitigation_stats;

  return (
    <div className="attack-container">
      {/* Top Header / Subbar */}
      <div className="attack-subbar">
        <div className="subbar-controls">
          <div className="control-group">
            <span className="control-label">AI TARGET:</span>
            <div className="model-toggle-pill mini">
              <button
                className={`model-option ${selectedProvider === "claude" ? "active" : ""}`}
                onClick={() => setSelectedProvider("claude")}
                disabled={isRunningAll || runningScenarioId}
              >
                Claude (claude-sonnet-5-5)
              </button>
              <button
                className={`model-option ${selectedProvider === "gemini" ? "active" : ""}`}
                onClick={() => setSelectedProvider("gemini")}
                disabled={isRunningAll || runningScenarioId}
              >
                Gemini (gemini-3.8-flash)
              </button>
            </div>
          </div>

          <div className="control-group">
            <span className="control-label">EVALUATION STAGE:</span>
            <div className="model-toggle-pill mini">
              <button
                className={`model-option ${selectedStage === "BASELINE" ? "active" : ""}`}
                onClick={() => setSelectedStage("BASELINE")}
                disabled={isRunningAll || runningScenarioId}
              >
                BASELINE (Pre-Mitigation)
              </button>
              <button
                className={`model-option ${selectedStage === "POST_MITIGATION" ? "active" : ""}`}
                onClick={() => setSelectedStage("POST_MITIGATION")}
                disabled={isRunningAll || runningScenarioId}
              >
                POST-MITIGATION
              </button>
            </div>
          </div>

          <div className="control-group">
            <span className="control-label">ROLE CONTEXT:</span>
            <select
              className="role-selector"
              value={selectedRole}
              onChange={(e) => setSelectedRole(e.target.value)}
              disabled={isRunningAll || runningScenarioId}
            >
              <option value="analyst">Analyst</option>
              <option value="user">User</option>
              <option value="admin">Admin</option>
            </select>
          </div>
        </div>

        <div className="subbar-actions">
          <button
            className="btn-batch-run"
            onClick={() => handleRunBatch()}
            disabled={isRunningAll || runningScenarioId}
          >
            {isRunningAll ? "⏳ Running Batch..." : "⚡ Run All 30 Attacks"}
          </button>
          <button className="reset-btn" onClick={refreshSummary} title="Refresh Summary">
            ↺ Refresh
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

      {/* Metrics Banner */}
      <div className="attack-metrics-strip">
        <div className="metric-box">
          <span className="metric-label">TOTAL SCENARIOS</span>
          <span className="metric-value">30</span>
          <span className="metric-sub">10 OWASP Risks (3 each)</span>
        </div>
        <div className="metric-box">
          <span className="metric-label">STAGE</span>
          <span className="metric-value stage-tag">{selectedStage}</span>
          <span className="metric-sub">{selectedProvider.toUpperCase()}</span>
        </div>
        <div className="metric-box">
          <span className="metric-label">TESTS EXECUTED</span>
          <span className="metric-value">{currentStageStats?.total || 0}</span>
          <span className="metric-sub">Recorded in SQLite</span>
        </div>
        <div className="metric-box">
          <span className="metric-label">DEFENSE BLOCK RATE</span>
          <span className="metric-value highlight">{currentStageStats?.block_rate_percent || 0}%</span>
          <span className="metric-sub">{currentStageStats?.blocked || 0} Blocked / {currentStageStats?.total || 0}</span>
        </div>
        <div className="metric-box counts-box">
          <span className="metric-label">OUTCOME BREAKDOWN</span>
          <div className="breakdown-pills">
            <span className="pill-blocked">🛡️ {currentStageStats?.blocked || 0} BLOCKED</span>
            <span className="pill-partial">⚠️ {currentStageStats?.partial || 0} PARTIAL</span>
            <span className="pill-succeeded">❌ {currentStageStats?.succeeded || 0} SUCCEEDED</span>
          </div>
        </div>
      </div>

      {/* Main Workspace */}
      <div className="attack-workspace">
        {/* Left: Risk Filters Navigation */}
        <aside className="risk-sidebar">
          <div className="risk-sidebar-header">
            <span>OWASP SECURITY RISKS</span>
          </div>

          <div className="risk-menu">
            <button
              className={`risk-menu-item ${activeRiskFilter === "ALL" ? "active" : ""}`}
              onClick={() => setActiveRiskFilter("ALL")}
            >
              <div className="risk-title">
                <strong>All 10 Risks</strong>
                <span className="count-pill">30 Scenarios</span>
              </div>
            </button>

            <div className="risk-group-title">OWASP TOP 10 FOR LLM</div>
            {risks.filter((r) => r.category === "OWASP_LLM").map((r) => (
              <button
                key={r.risk_id}
                className={`risk-menu-item ${activeRiskFilter === r.risk_id ? "active" : ""}`}
                onClick={() => setActiveRiskFilter(r.risk_id)}
              >
                <div className="risk-title">
                  <code>{r.risk_id}</code>
                  <span>{r.risk_name}</span>
                </div>
                <span className="count-pill">3</span>
              </button>
            ))}

            <div className="risk-group-title">OWASP AGENTIC AI RISKS</div>
            {risks.filter((r) => r.category === "OWASP_AGENTIC").map((r) => (
              <button
                key={r.risk_id}
                className={`risk-menu-item ${activeRiskFilter === r.risk_id ? "active" : ""}`}
                onClick={() => setActiveRiskFilter(r.risk_id)}
              >
                <div className="risk-title">
                  <code>{r.risk_id}</code>
                  <span>{r.risk_name}</span>
                </div>
                <span className="count-pill">3</span>
              </button>
            ))}
          </div>
        </aside>

        {/* Right: Scenarios Grid */}
        <main className="scenarios-pane">
          <div className="pane-header">
            <div className="pane-title">
              <h3>
                {activeRiskFilter === "ALL" ? "All 30 Attack Scenarios" : `${activeRiskFilter} Scenarios`}
              </h3>
              <span className="pane-sub">
                Targeting: {selectedProvider.toUpperCase()} · Stage: {selectedStage}
              </span>
            </div>

            {activeRiskFilter !== "ALL" && (
              <button
                className="btn-batch-risk"
                onClick={() => handleRunBatch(activeRiskFilter)}
                disabled={isRunningAll || runningScenarioId}
              >
                ▶ Run All 3 {activeRiskFilter} Scenarios
              </button>
            )}
          </div>

          <div className="scenarios-grid">
            {filteredScenarios.map((sc) => {
              const res = resultsMap[sc.scenario_id];
              const isExecuting = runningScenarioId === sc.scenario_id;

              return (
                <div key={sc.scenario_id} className="scenario-card">
                  <div className="card-top-bar">
                    <div className="card-id-group">
                      <span className="scenario-id-pill">{sc.scenario_id}</span>
                      <span className={`severity-tag sev-${sc.severity}`}>{sc.severity.toUpperCase()}</span>
                      <span className="component-tag">{sc.target_component.toUpperCase()}</span>
                    </div>
                    <div className="result-status">
                      {isExecuting ? (
                        <span className="status-badge badge-pending">⏳ RUNNING...</span>
                      ) : (
                        getResultBadge(sc.scenario_id)
                      )}
                    </div>
                  </div>

                  <h4 className="scenario-title">{sc.scenario_name}</h4>
                  <p className="scenario-desc">{sc.attack_description}</p>

                  <div className="prompt-preview-box">
                    <div className="prompt-label">ATTACK PROMPT:</div>
                    <code className="prompt-text">"{sc.attack_prompt}"</code>
                  </div>

                  <div className="secure-behavior-box">
                    <div className="prompt-label">EXPECTED SECURE BEHAVIOR:</div>
                    <span className="behavior-text">{sc.expected_secure_behavior}</span>
                  </div>

                  {res && (
                    <div className="result-snapshot">
                      <div className="snapshot-header">
                        <span>LATEST OUTCOME ({res.stage}):</span>
                        <span className="res-time">⚡ {res.latency_ms}ms</span>
                      </div>
                      <p className="eval-reason">{res.evaluation_reason}</p>
                    </div>
                  )}

                  <div className="card-footer-actions">
                    <button
                      className="btn-run-scenario"
                      onClick={() => handleRunSingle(sc.scenario_id)}
                      disabled={isExecuting || isRunningAll}
                    >
                      {isExecuting ? "Executing..." : "▶ Run Attack"}
                    </button>
                    {res && (
                      <button
                        className="btn-view-trace"
                        onClick={() => setSelectedResultModal(res)}
                      >
                        Inspect Result & Trace
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </main>
      </div>

      {/* Result Detail Modal */}
      {selectedResultModal && (
        <div className="modal-backdrop" onClick={() => setSelectedResultModal(null)}>
          <div className="result-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-header-left">
                <h3>ATTACK EVALUATION TRACE</h3>
                <span className="scenario-id-pill">{selectedResultModal.scenario_id}</span>
                <span className="stage-tag">{selectedResultModal.stage}</span>
              </div>
              <button className="modal-close" onClick={() => setSelectedResultModal(null)}>
                ✕
              </button>
            </div>

            <div className="modal-body">
              <div className="eval-verdict-card">
                <div className="verdict-top">
                  <span className="verdict-label">SECURITY VERDICT:</span>
                  <span className={`status-badge badge-${selectedResultModal.result_classification === "BLOCKED" ? "success" : selectedResultModal.result_classification === "SUCCEEDED" ? "denied" : "pending"}`}>
                    {selectedResultModal.result_classification}
                  </span>
                </div>
                <p className="verdict-reason">{selectedResultModal.evaluation_reason}</p>
                <div className="verdict-meta">
                  <span>Provider: <b>{selectedResultModal.provider}</b></span>
                  <span>Model: <b>{selectedResultModal.model}</b></span>
                  <span>Execution Mode: <b>{selectedResultModal.execution_mode}</b></span>
                  <span>Latency: <b>{selectedResultModal.latency_ms}ms</b></span>
                </div>
              </div>

              <div className="modal-section">
                <span className="section-label">ATTACK PROMPT SENT:</span>
                <pre className="code-block">{selectedResultModal.prompt}</pre>
              </div>

              <div className="modal-section">
                <span className="section-label">MODEL RESPONSE:</span>
                <pre className="code-block result-block">
                  {selectedResultModal.response_content || "No response text captured."}
                </pre>
              </div>

              {selectedResultModal.tool_calls && selectedResultModal.tool_calls.length > 0 && (
                <div className="modal-section">
                  <span className="section-label">TOOL EXECUTION TRACE ({selectedResultModal.tool_calls.length}):</span>
                  <pre className="code-block">
                    {JSON.stringify(selectedResultModal.tool_calls, null, 2)}
                  </pre>
                </div>
              )}
            </div>

            <div className="modal-footer">
              <span className="modal-time">Executed at: {new Date(selectedResultModal.created_at).toLocaleString()}</span>
              <button className="btn-close-modal" onClick={() => setSelectedResultModal(null)}>
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

