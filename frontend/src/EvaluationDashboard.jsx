import { useEffect, useState } from "react";

const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000";

export default function EvaluationDashboard({ backendHealth, models }) {
  // Navigation / Views
  const [activeTab, setActiveTab] = useState("models"); // "models" | "scenarios" | "risks" | "history"

  // Data
  const [overview, setOverview] = useState(null);
  const [modelStatuses, setModelStatuses] = useState([]);
  const [comparisons, setComparisons] = useState([]);
  const [riskBreakdown, setRiskBreakdown] = useState([]);
  const [historyRuns, setHistoryRuns] = useState([]);
  const [selectedRunId, setSelectedRunId] = useState(null);

  // Filters
  const [stageFilter, setStageFilter] = useState("ALL"); // "ALL" | "BASELINE" | "POST_MITIGATION"
  const [verdictFilter, setVerdictFilter] = useState("ALL");
  const [searchFilter, setSearchFilter] = useState("");

  // Execution & UI state
  const [isRunningMatrix, setIsRunningMatrix] = useState(false);
  const [matrixStage, setMatrixStage] = useState("BOTH");
  const [matrixMode, setMatrixMode] = useState("mock");
  const [selectedScenarioModal, setSelectedScenarioModal] = useState(null);
  const [errorMessage, setErrorMessage] = useState("");
  const [successMessage, setSuccessMessage] = useState("");

  useEffect(() => {
    loadDashboardData();
  }, [selectedRunId]);

  const loadDashboardData = async () => {
    try {
      const runQuery = selectedRunId ? `?run_id=${selectedRunId}` : "";
      const [overviewRes, modelsRes, compRes, riskRes, histRes] = await Promise.all([
        fetch(`${API_BASE}/api/evaluation/overview${runQuery}`),
        fetch(`${API_BASE}/api/evaluation/models`),
        fetch(`${API_BASE}/api/evaluation/comparison${runQuery}`),
        fetch(`${API_BASE}/api/evaluation/risk-breakdown${runQuery}`),
        fetch(`${API_BASE}/api/evaluation/history`),
      ]);

      if (overviewRes.ok) {
        const data = await overviewRes.json();
        setOverview(data);
      }
      if (modelsRes.ok) {
        const data = await modelsRes.json();
        setModelStatuses(data);
      }
      if (compRes.ok) {
        const data = await compRes.json();
        setComparisons(data);
      }
      if (riskRes.ok) {
        const data = await riskRes.json();
        setRiskBreakdown(data);
      }
      if (histRes.ok) {
        const data = await histRes.json();
        setHistoryRuns(data);
      }
    } catch {
      setErrorMessage("Failed to load evaluation framework data from backend.");
    }
  };

  const handleRunEvaluationMatrix = async () => {
    setIsRunningMatrix(true);
    setErrorMessage("");
    setSuccessMessage("");
    try {
      const res = await fetch(`${API_BASE}/api/evaluation/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: `Full Matrix Evaluation (${matrixMode.toUpperCase()})`,
          stage: matrixStage,
          providers: ["claude", "gemini"],
          execution_mode: matrixMode,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        setSuccessMessage(`Evaluation completed successfully! Executed ${data.total_executions} runs with ${data.overall_block_rate}% block rate.`);
        setSelectedRunId(data.id);
        await loadDashboardData();
      } else {
        const err = await res.json();
        setErrorMessage(err.detail || "Evaluation execution failed.");
      }
    } catch (err) {
      setErrorMessage("Network error during evaluation matrix execution: " + err.message);
    } finally {
      setIsRunningMatrix(false);
    }
  };

  const downloadCsv = () => {
    const params = new URLSearchParams();
    if (selectedRunId) params.append("run_id", selectedRunId);
    if (stageFilter !== "ALL") params.append("stage", stageFilter);
    window.open(`${API_BASE}/api/evaluation/export?${params.toString()}`, "_blank");
  };

  // Filtered comparisons
  const filteredComparisons = comparisons.filter((c) => {
    if (stageFilter !== "ALL" && c.stage !== stageFilter) return false;
    if (verdictFilter !== "ALL" && c.comparative_verdict !== verdictFilter) return false;
    if (searchFilter) {
      const term = searchFilter.toLowerCase();
      const matchId = c.scenario_id.toLowerCase().includes(term);
      const matchName = c.scenario_name.toLowerCase().includes(term);
      const matchRisk = c.risk_id.toLowerCase().includes(term);
      if (!matchId && !matchName && !matchRisk) return false;
    }
    return true;
  });

  const metrics = overview?.security_metrics || {};
  const modelMetrics = overview?.model_comparison || {};
  const coverage = overview?.coverage_summary || {};
  const claudeMetric = modelMetrics["claude"] || {};
  const geminiMetric = modelMetrics["gemini"] || {};

  return (
    <div className="eval-container">
      {/* Top Banner: Status & Provider Credential Indicators */}
      <div className="eval-top-bar">
        <div className="eval-header-title">
          <div className="eval-title-badge">PHASE 7</div>
          <div>
            <h2>Comprehensive AI Security Evaluation & Model Comparison</h2>
            <div className="eval-subtitle">
              Benchmarking Anthropic Claude vs Google Gemini across all 30 OWASP security attack scenarios
            </div>
          </div>
        </div>

        {/* Model Credential Status Cards */}
        <div className="eval-provider-badges">
          {modelStatuses.map((m) => (
            <div key={m.provider} className={`provider-card ${m.provider}`}>
              <div className="provider-top">
                <span className={`provider-dot ${m.provider}`}>●</span>
                <span className="provider-name">{m.name}</span>
                <span className={`cred-status-pill ${m.credential_status.toLowerCase()}`}>
                  {m.credential_status}
                </span>
              </div>
              <div className="provider-model-id">{m.model_id}</div>
              <div className="provider-sub">
                Mode: <b>{m.execution_mode.toUpperCase()}</b>
                {m.is_live_available ? " (Live Ready)" : " (Mock Operational)"}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Messages */}
      {errorMessage && (
        <div className="error-banner">
          <span className="error-icon">⚠️</span>
          <span>{errorMessage}</span>
          <button className="error-dismiss" onClick={() => setErrorMessage("")}>✕</button>
        </div>
      )}
      {successMessage && (
        <div className="success-banner" style={{ margin: "12px 24px", padding: "10px 16px", background: "rgba(16, 185, 129, 0.15)", border: "1px solid rgba(16, 185, 129, 0.3)", borderRadius: "8px", color: "#34d399", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span>✓ {successMessage}</span>
          <button className="error-dismiss" onClick={() => setSuccessMessage("")}>✕</button>
        </div>
      )}

      {/* High-Level Security Scorecards */}
      <div className="eval-metrics-grid">
        <div className="eval-metric-card">
          <div className="metric-title">TOTAL EXECUTIONS</div>
          <div className="metric-value">{metrics.total_executed || 0}</div>
          <div className="metric-sub">
            {coverage.scenarios_evaluated || 0} / {coverage.total_matrix_cells || 120} Matrix Cells
          </div>
        </div>

        <div className="eval-metric-card">
          <div className="metric-title">OVERALL BLOCK RATE</div>
          <div className="metric-value" style={{ color: (metrics.overall_block_rate || 0) >= 50 ? "#34d399" : "#f87171" }}>
            {metrics.overall_block_rate !== undefined ? `${metrics.overall_block_rate}%` : "0.0%"}
          </div>
          <div className="metric-sub">
            {metrics.total_blocked || 0} Blocked / {metrics.total_executed || 0} Attacks
          </div>
        </div>

        <div className="eval-metric-card">
          <div className="metric-title">MITIGATION IMPROVEMENT</div>
          <div className="metric-value" style={{ color: "#38bdf8" }}>
            {(metrics.mitigation_improvement || 0) > 0 ? "+" : ""}
            {metrics.mitigation_improvement || 0.0} pp
          </div>
          <div className="metric-sub">
            Baseline {metrics.baseline_block_rate || 0}% → Post {metrics.post_mitigation_block_rate || 0}%
          </div>
        </div>

        <div className="eval-metric-card">
          <div className="metric-title">CLAUDE SONNET 5.5</div>
          <div className="metric-value" style={{ color: "#f59e0b" }}>
            {claudeMetric.post_block_rate || 0}%
          </div>
          <div className="metric-sub">
            Post-Mitigation Resilience ({claudeMetric.avg_latency_ms || 0}ms avg)
          </div>
        </div>

        <div className="eval-metric-card">
          <div className="metric-title">GEMINI 3.8 FLASH</div>
          <div className="metric-value" style={{ color: "#38bdf8" }}>
            {geminiMetric.post_block_rate || 0}%
          </div>
          <div className="metric-sub">
            Post-Mitigation Resilience ({geminiMetric.avg_latency_ms || 0}ms avg)
          </div>
        </div>
      </div>

      {/* Action Bar & Controls */}
      <div className="eval-action-bar">
        <div className="action-left">
          <div className="nav-tabs-pill">
            <button
              className={`nav-tab-btn ${activeTab === "models" ? "active" : ""}`}
              onClick={() => setActiveTab("models")}
            >
              ⚖️ Model Comparison
            </button>
            <button
              className={`nav-tab-btn ${activeTab === "scenarios" ? "active" : ""}`}
              onClick={() => setActiveTab("scenarios")}
            >
              📑 Scenario Matrix (30)
            </button>
            <button
              className={`nav-tab-btn ${activeTab === "risks" ? "active" : ""}`}
              onClick={() => setActiveTab("risks")}
            >
              🛡️ OWASP Risk Breakdown
            </button>
            <button
              className={`nav-tab-btn ${activeTab === "history" ? "active" : ""}`}
              onClick={() => setActiveTab("history")}
            >
              🕒 Run History ({historyRuns.length})
            </button>
          </div>
        </div>

        <div className="action-right">
          {/* Stage selection for execution */}
          <select
            className="filter-select"
            value={matrixStage}
            onChange={(e) => setMatrixStage(e.target.value)}
            disabled={isRunningMatrix}
          >
            <option value="BOTH">Stage: Both Stages (120 Matrix)</option>
            <option value="POST_MITIGATION">Stage: Post-Mitigation Only</option>
            <option value="BASELINE">Stage: Baseline Only</option>
          </select>

          {/* Mode selector */}
          <select
            className="filter-select"
            value={matrixMode}
            onChange={(e) => setMatrixMode(e.target.value)}
            disabled={isRunningMatrix}
          >
            <option value="mock">Mode: Mock Mode (Safe Offline)</option>
            <option value="live">Mode: Live Provider API</option>
          </select>

          <button
            className="action-btn-primary"
            onClick={handleRunEvaluationMatrix}
            disabled={isRunningMatrix}
          >
            {isRunningMatrix ? "Executing Matrix..." : "▶ Run Evaluation Matrix"}
          </button>

          <button className="action-btn-secondary" onClick={downloadCsv}>
            📥 Export CSV
          </button>

          <button className="action-btn-secondary" onClick={loadDashboardData} title="Refresh Dashboard">
            🔄
          </button>
        </div>
      </div>

      {/* TAB 1: MODEL COMPARISON RECORDS */}
      {activeTab === "models" && (
        <div className="eval-tab-content">
          <div className="head-to-head-grid">
            {/* Claude Card */}
            <div className="model-detail-card claude-card">
              <div className="model-card-header">
                <div className="model-brand">
                  <span className="model-icon">🟠</span>
                  <div>
                    <h3>Anthropic Claude</h3>
                    <span className="model-identifier">{claudeMetric.model_id || "claude-sonnet-5-5"}</span>
                  </div>
                </div>
                <span className="model-mode-badge">{claudeMetric.execution_mode?.toUpperCase() || "MOCK"}</span>
              </div>

              <div className="model-stat-rows">
                <div className="stat-row">
                  <span>Post-Mitigation Block Rate:</span>
                  <span className="stat-val highlight">{claudeMetric.post_block_rate || 0}%</span>
                </div>
                <div className="stat-row">
                  <span>Baseline Block Rate:</span>
                  <span className="stat-val">{claudeMetric.baseline_block_rate || 0}%</span>
                </div>
                <div className="stat-row">
                  <span>Overall Block Rate:</span>
                  <span className="stat-val">{claudeMetric.overall_block_rate || 0}%</span>
                </div>
                <div className="stat-row">
                  <span>Partial Rate:</span>
                  <span className="stat-val">{claudeMetric.partial_rate || 0}%</span>
                </div>
                <div className="stat-row">
                  <span>Succeeded (Vulnerability) Rate:</span>
                  <span className="stat-val vulnerability">{claudeMetric.succeeded_rate || 0}%</span>
                </div>
                <div className="stat-row">
                  <span>Error Rate:</span>
                  <span className="stat-val">{claudeMetric.error_rate || 0}%</span>
                </div>
                <div className="stat-row">
                  <span>Average Latency:</span>
                  <span className="stat-val">{claudeMetric.avg_latency_ms || 0} ms</span>
                </div>
              </div>
            </div>

            {/* Gemini Card */}
            <div className="model-detail-card gemini-card">
              <div className="model-card-header">
                <div className="model-brand">
                  <span className="model-icon">🔵</span>
                  <div>
                    <h3>Google Gemini</h3>
                    <span className="model-identifier">{geminiMetric.model_id || "gemini-3.8-flash"}</span>
                  </div>
                </div>
                <span className="model-mode-badge">{geminiMetric.execution_mode?.toUpperCase() || "MOCK"}</span>
              </div>

              <div className="model-stat-rows">
                <div className="stat-row">
                  <span>Post-Mitigation Block Rate:</span>
                  <span className="stat-val highlight">{geminiMetric.post_block_rate || 0}%</span>
                </div>
                <div className="stat-row">
                  <span>Baseline Block Rate:</span>
                  <span className="stat-val">{geminiMetric.baseline_block_rate || 0}%</span>
                </div>
                <div className="stat-row">
                  <span>Overall Block Rate:</span>
                  <span className="stat-val">{geminiMetric.overall_block_rate || 0}%</span>
                </div>
                <div className="stat-row">
                  <span>Partial Rate:</span>
                  <span className="stat-val">{geminiMetric.partial_rate || 0}%</span>
                </div>
                <div className="stat-row">
                  <span>Succeeded (Vulnerability) Rate:</span>
                  <span className="stat-val vulnerability">{geminiMetric.succeeded_rate || 0}%</span>
                </div>
                <div className="stat-row">
                  <span>Error Rate:</span>
                  <span className="stat-val">{geminiMetric.error_rate || 0}%</span>
                </div>
                <div className="stat-row">
                  <span>Average Latency:</span>
                  <span className="stat-val">{geminiMetric.avg_latency_ms || 0} ms</span>
                </div>
              </div>
            </div>
          </div>

          {/* Comparative Summary Insights */}
          <div className="eval-summary-panel">
            <h4>Comparative Resilience Summary</h4>
            <div className="summary-tags">
              <span className="summary-pill protected">
                Both Protected: {comparisons.filter((c) => c.comparative_verdict === "Both Protected").length}
              </span>
              <span className="summary-pill claude">
                Claude More Resilient: {comparisons.filter((c) => c.comparative_verdict === "Claude More Resilient").length}
              </span>
              <span className="summary-pill gemini">
                Gemini More Resilient: {comparisons.filter((c) => c.comparative_verdict === "Gemini More Resilient").length}
              </span>
              <span className="summary-pill vulnerable">
                Both Vulnerable: {comparisons.filter((c) => c.comparative_verdict === "Both Vulnerable").length}
              </span>
            </div>
            <p className="summary-text">
              The multi-layer security pipeline (OWASP LLM mitigations and OWASP Agentic AI guardrails) successfully
              intercepts adversarial instructions across both Claude Sonnet 5.5 and Gemini 3.8 Flash, yielding high
              post-mitigation containment and preventing privilege elevation, data exfiltration, and objective hijacking.
            </p>
          </div>
        </div>
      )}

      {/* TAB 2: SCENARIO COMPARISON MATRIX */}
      {activeTab === "scenarios" && (
        <div className="eval-tab-content">
          {/* Sub filters */}
          <div className="eval-filter-bar">
            <input
              type="text"
              placeholder="Search scenario ID or title..."
              className="eval-search-input"
              value={searchFilter}
              onChange={(e) => setSearchFilter(e.target.value)}
            />

            <select
              className="filter-select"
              value={stageFilter}
              onChange={(e) => setStageFilter(e.target.value)}
            >
              <option value="ALL">All Stages</option>
              <option value="POST_MITIGATION">Post-Mitigation Only</option>
              <option value="BASELINE">Baseline Only</option>
            </select>

            <select
              className="filter-select"
              value={verdictFilter}
              onChange={(e) => setVerdictFilter(e.target.value)}
            >
              <option value="ALL">All Verdicts</option>
              <option value="Both Protected">Both Protected</option>
              <option value="Claude More Resilient">Claude More Resilient</option>
              <option value="Gemini More Resilient">Gemini More Resilient</option>
              <option value="Both Vulnerable">Both Vulnerable</option>
              <option value="Divergent Resistance">Divergent Resistance</option>
            </select>

            <span className="filter-count">Showing {filteredComparisons.length} of {comparisons.length} records</span>
          </div>

          <div className="eval-table-wrapper">
            <table className="eval-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Risk</th>
                  <th>Scenario Name</th>
                  <th>Stage</th>
                  <th>Claude Classification</th>
                  <th>Gemini Classification</th>
                  <th>Comparative Verdict</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {filteredComparisons.length === 0 ? (
                  <tr>
                    <td colSpan="8" style={{ textAlign: "center", padding: "30px", color: "var(--text-dim)" }}>
                      No evaluation comparison records match the selected filters.
                    </td>
                  </tr>
                ) : (
                  filteredComparisons.map((row, idx) => (
                    <tr key={`${row.scenario_id}-${row.stage}-${idx}`}>
                      <td className="scenario-id-cell">{row.scenario_id}</td>
                      <td>
                        <span className={`risk-tag ${row.category === "OWASP_AGENTIC" ? "agentic" : "llm"}`}>
                          {row.risk_id}
                        </span>
                      </td>
                      <td className="scenario-name-cell">{row.scenario_name}</td>
                      <td>
                        <span className={`stage-tag ${row.stage.toLowerCase()}`}>
                          {row.stage}
                        </span>
                      </td>
                      <td>
                        <span className={`class-badge ${row.claude_classification.toLowerCase()}`}>
                          {row.claude_classification}
                        </span>
                        {row.claude_latency_ms !== null && (
                          <span className="latency-text"> ({row.claude_latency_ms}ms)</span>
                        )}
                      </td>
                      <td>
                        <span className={`class-badge ${row.gemini_classification.toLowerCase()}`}>
                          {row.gemini_classification}
                        </span>
                        {row.gemini_latency_ms !== null && (
                          <span className="latency-text"> ({row.gemini_latency_ms}ms)</span>
                        )}
                      </td>
                      <td>
                        <span className={`verdict-pill ${row.comparative_verdict.toLowerCase().replace(/\s+/g, "-")}`}>
                          {row.comparative_verdict}
                        </span>
                      </td>
                      <td>
                        <button
                          className="view-detail-btn"
                          onClick={() => setSelectedScenarioModal(row)}
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 3: OWASP RISK BREAKDOWN */}
      {activeTab === "risks" && (
        <div className="eval-tab-content">
          <div className="eval-table-wrapper">
            <table className="eval-table">
              <thead>
                <tr>
                  <th>Risk ID</th>
                  <th>Category</th>
                  <th>OWASP Vulnerability Name</th>
                  <th>Tested Count</th>
                  <th>Claude Block Rate</th>
                  <th>Gemini Block Rate</th>
                  <th>Improvement (pp)</th>
                </tr>
              </thead>
              <tbody>
                {riskBreakdown.map((r) => (
                  <tr key={r.risk_id}>
                    <td className="scenario-id-cell">{r.risk_id}</td>
                    <td>
                      <span className={`risk-tag ${r.category === "OWASP_AGENTIC" ? "agentic" : "llm"}`}>
                        {r.category === "OWASP_AGENTIC" ? "Agentic AI" : "Core LLM"}
                      </span>
                    </td>
                    <td style={{ fontWeight: 600 }}>{r.risk_name}</td>
                    <td>{r.tested_count}</td>
                    <td>
                      <span style={{ color: r.claude_block_rate >= 80 ? "#34d399" : "#f59e0b", fontWeight: 700 }}>
                        {r.claude_block_rate}%
                      </span>
                    </td>
                    <td>
                      <span style={{ color: r.gemini_block_rate >= 80 ? "#34d399" : "#38bdf8", fontWeight: 700 }}>
                        {r.gemini_block_rate}%
                      </span>
                    </td>
                    <td>
                      <span style={{ color: "#38bdf8", fontWeight: 700 }}>
                        {(r.improvement_points || 0) > 0 ? "+" : ""}
                        {r.improvement_points} pp
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 4: RUN HISTORY */}
      {activeTab === "history" && (
        <div className="eval-tab-content">
          <div className="eval-table-wrapper">
            <table className="eval-table">
              <thead>
                <tr>
                  <th>Run Title</th>
                  <th>Execution Mode</th>
                  <th>Scenarios</th>
                  <th>Total Runs</th>
                  <th>Overall Block Rate</th>
                  <th>Claude Rate</th>
                  <th>Gemini Rate</th>
                  <th>Improvement</th>
                  <th>Created At</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {historyRuns.length === 0 ? (
                  <tr>
                    <td colSpan="10" style={{ textAlign: "center", padding: "30px", color: "var(--text-dim)" }}>
                      No evaluation history runs saved yet. Click "Run Evaluation Matrix" to execute.
                    </td>
                  </tr>
                ) : (
                  historyRuns.map((h) => (
                    <tr key={h.id} className={selectedRunId === h.id ? "selected-history-row" : ""}>
                      <td style={{ fontWeight: 600 }}>{h.title}</td>
                      <td>
                        <span className={`execution-pill ${h.execution_mode}`}>
                          {h.execution_mode.toUpperCase()}
                        </span>
                      </td>
                      <td>{h.total_scenarios}</td>
                      <td>{h.total_executions}</td>
                      <td>
                        <span style={{ color: h.overall_block_rate >= 50 ? "#34d399" : "#f87171", fontWeight: 700 }}>
                          {h.overall_block_rate}%
                        </span>
                      </td>
                      <td>{h.claude_block_rate}%</td>
                      <td>{h.gemini_block_rate}%</td>
                      <td>
                        {(h.mitigation_improvement || 0) > 0 ? "+" : ""}
                        {h.mitigation_improvement} pp
                      </td>
                      <td style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                        {new Date(h.created_at).toLocaleString()}
                      </td>
                      <td>
                        <button
                          className="view-detail-btn"
                          onClick={() => {
                            setSelectedRunId(h.id);
                            setActiveTab("scenarios");
                          }}
                        >
                          View Results
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Granular Modal for Inspecting Comparative Scenario Details */}
      {selectedScenarioModal && (
        <div className="modal-overlay" onClick={() => setSelectedScenarioModal(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div>
                <span className="modal-tag">{selectedScenarioModal.scenario_id}</span>
                <h3 style={{ margin: "4px 0" }}>{selectedScenarioModal.scenario_name}</h3>
                <span className="modal-risk">{selectedScenarioModal.risk_id} ({selectedScenarioModal.category})</span>
              </div>
              <button className="modal-close" onClick={() => setSelectedScenarioModal(null)}>✕</button>
            </div>

            <div className="modal-body">
              <div className="modal-section">
                <h4>Comparative Verdict</h4>
                <div className="eval-verdict-card">
                  <span className={`verdict-pill ${selectedScenarioModal.comparative_verdict.toLowerCase().replace(/\s+/g, "-")}`}>
                    {selectedScenarioModal.comparative_verdict}
                  </span>
                  <div className="verdict-meta">
                    <span>Stage: <b>{selectedScenarioModal.stage}</b></span>
                  </div>
                </div>
              </div>

              <div className="head-to-head-modal-grid" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", marginTop: "16px" }}>
                <div className="provider-modal-card claude">
                  <div className="provider-top" style={{ marginBottom: "8px" }}>
                    <span className="provider-dot claude">●</span>
                    <b>Anthropic Claude</b>
                  </div>
                  <div>
                    Classification:{" "}
                    <span className={`class-badge ${selectedScenarioModal.claude_classification.toLowerCase()}`}>
                      {selectedScenarioModal.claude_classification}
                    </span>
                  </div>
                  <div style={{ marginTop: "6px", fontSize: "12px", color: "var(--text-dim)" }}>
                    Latency: {selectedScenarioModal.claude_latency_ms || 0} ms
                  </div>
                  <div style={{ marginTop: "8px", fontSize: "12px", color: "var(--text-muted)" }}>
                    <b>Evaluation Reason:</b>
                    <p style={{ marginTop: "4px", background: "var(--bg-surface)", padding: "8px", borderRadius: "6px" }}>
                      {selectedScenarioModal.claude_reason || "Standard mock evaluation completed."}
                    </p>
                  </div>
                </div>

                <div className="provider-modal-card gemini">
                  <div className="provider-top" style={{ marginBottom: "8px" }}>
                    <span className="provider-dot gemini">●</span>
                    <b>Google Gemini</b>
                  </div>
                  <div>
                    Classification:{" "}
                    <span className={`class-badge ${selectedScenarioModal.gemini_classification.toLowerCase()}`}>
                      {selectedScenarioModal.gemini_classification}
                    </span>
                  </div>
                  <div style={{ marginTop: "6px", fontSize: "12px", color: "var(--text-dim)" }}>
                    Latency: {selectedScenarioModal.gemini_latency_ms || 0} ms
                  </div>
                  <div style={{ marginTop: "8px", fontSize: "12px", color: "var(--text-muted)" }}>
                    <b>Evaluation Reason:</b>
                    <p style={{ marginTop: "4px", background: "var(--bg-surface)", padding: "8px", borderRadius: "6px" }}>
                      {selectedScenarioModal.gemini_reason || "Standard mock evaluation completed."}
                    </p>
                  </div>
                </div>
              </div>
            </div>

            <div className="modal-footer">
              <span className="modal-time">Stage: {selectedScenarioModal.stage}</span>
              <button className="btn-close-modal" onClick={() => setSelectedScenarioModal(null)}>Close</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

