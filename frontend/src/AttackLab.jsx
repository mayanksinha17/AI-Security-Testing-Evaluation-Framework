import { useEffect, useState } from "react";

const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000";

export default function AttackLab({ backendHealth, models }) {
  // Resolve model metadata from backend /api/models with authoritative fallbacks
  const claudeModel = models?.find((m) => m.id === "claude")?.model || "claude-sonnet-5";
  const geminiModel = models?.find((m) => m.id === "gemini")?.model || "gemini-3.8-flash";

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
  const [latestBatchResult, setLatestBatchResult] = useState(null);

  // Export state
  const [isDownloadingPdf, setIsDownloadingPdf] = useState(false);
  const [isDownloadingCsv, setIsDownloadingCsv] = useState(false);
  const [exportError, setExportError] = useState(null);

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
        model: selectedProvider === "claude" ? claudeModel : geminiModel,
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

  const handleRunBatch = async (explicitRiskFilter = undefined) => {
    if (isRunningAll || runningScenarioId) return;
    setIsRunningAll(true);
    setErrorMessage("");
    setExportError(null);
    const startTime = Date.now();

    const targetRiskId = explicitRiskFilter !== undefined
      ? explicitRiskFilter
      : (activeRiskFilter !== "ALL" ? activeRiskFilter : null);

    try {
      const payload = {
        risk_id: targetRiskId,
        provider: selectedProvider,
        model: selectedProvider === "claude" ? claudeModel : geminiModel,
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

      // Duration calculation
      const totalLatency = runResponse.results?.reduce((sum, r) => sum + (r.latency_ms || 0), 0) || 0;
      const durationMs = runResponse.duration_ms || Math.round(totalLatency) || (Date.now() - startTime);

      const executedCount = runResponse.results ? runResponse.results.length : runResponse.total_scenarios;
      const blocked = runResponse.blocked_count;
      const partial = runResponse.partial_count;
      const succeeded = runResponse.succeeded_count;
      const errorCount = runResponse.error_count;

      // Consolidated risk-level verdict
      let verdict = "INCONCLUSIVE";
      let verdictClass = "badge-pending";
      let verdictDescription = "Batch execution returned inconclusive or error results.";

      if (succeeded > 0) {
        verdict = "VULNERABLE (EXPOSURE DETECTED)";
        verdictClass = "badge-denied";
        verdictDescription = `${succeeded} of ${executedCount} attacks succeeded in bypassing defenses.`;
      } else if (partial > 0) {
        verdict = "PARTIALLY MITIGATED (RESIDUAL RISK)";
        verdictClass = "badge-pending";
        verdictDescription = `${partial} attacks caused partial exposure or warning conditions.`;
      } else if (blocked === executedCount && executedCount > 0) {
        verdict = "SECURED (ALL ATTACKS BLOCKED)";
        verdictClass = "badge-success";
        verdictDescription = `All ${blocked} attack scenarios were successfully intercepted by guardrails.`;
      }

      setLatestBatchResult({
        runId: runResponse.id,
        riskId: targetRiskId || "ALL",
        totalScenarios: runResponse.total_scenarios,
        executedScenarios: executedCount,
        blockedCount: blocked,
        partialCount: partial,
        succeededCount: succeeded,
        errorCount: errorCount,
        durationMs: durationMs,
        stage: runResponse.stage,
        provider: runResponse.provider,
        model: runResponse.model,
        executionMode: runResponse.execution_mode,
        verdict,
        verdictClass,
        verdictDescription,
        executedAt: new Date().toLocaleTimeString(),
      });

      await refreshSummary();
    } catch (err) {
      setErrorMessage(err.message || "Failed to execute batch attack.");
    } finally {
      setIsRunningAll(false);
    }
  };

  const handleDownloadExport = async (format) => {
    if (!latestBatchResult || !latestBatchResult.runId) {
      setExportError("No active batch execution run ID available to export.");
      return;
    }

    setExportError(null);
    const isPdf = format === "pdf";
    if (isPdf) setIsDownloadingPdf(true);
    else setIsDownloadingCsv(true);

    try {
      const url = `${API_BASE}/api/attacks/runs/${latestBatchResult.runId}/export/${format}`;
      const response = await fetch(url);
      if (!response.ok) {
        let detail = `Failed to generate ${format.toUpperCase()} export (HTTP ${response.status})`;
        try {
          const errorJson = await response.json();
          if (errorJson.detail) detail = errorJson.detail;
        } catch (e) {}
        throw new Error(detail);
      }

      const blob = await response.blob();
      let filename = "";
      const disposition = response.headers.get("content-disposition");
      if (disposition && disposition.includes("filename=")) {
        const match = disposition.match(/filename="?([^"]+)"?/);
        if (match && match[1]) {
          filename = match[1];
        }
      }
      if (!filename) {
        const riskLabel = latestBatchResult.riskId || "Batch";
        filename = isPdf
          ? `ApexShield_${riskLabel}_Assessment_${latestBatchResult.runId}.pdf`
          : `ApexShield_${riskLabel}_Results_${latestBatchResult.runId}.csv`;
      }

      const downloadUrl = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = downloadUrl;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(downloadUrl);
    } catch (err) {
      console.error(`Export download error (${format}):`, err);
      setExportError(err.message || `Failed to download ${format.toUpperCase()}`);
    } finally {
      if (isPdf) setIsDownloadingPdf(false);
      else setIsDownloadingCsv(false);
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

  const riskResults = filteredScenarios.map((sc) => resultsMap[sc.scenario_id]).filter(Boolean);
  const riskStats = {
    executed: riskResults.length,
    blocked: riskResults.filter((r) => r.result_classification === "BLOCKED").length,
    partial: riskResults.filter((r) => r.result_classification === "PARTIAL").length,
    succeeded: riskResults.filter((r) => r.result_classification === "SUCCEEDED").length,
    blockRatePercent: riskResults.length > 0
      ? Math.round((riskResults.filter((r) => r.result_classification === "BLOCKED").length / riskResults.length) * 100)
      : 0,
  };

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
                Claude ({claudeModel})
              </button>
              <button
                className={`model-option ${selectedProvider === "gemini" ? "active" : ""}`}
                onClick={() => setSelectedProvider("gemini")}
                disabled={isRunningAll || runningScenarioId}
              >
                Gemini ({geminiModel})
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
            onClick={() => handleRunBatch(activeRiskFilter === "ALL" ? null : activeRiskFilter)}
            disabled={isRunningAll || runningScenarioId}
          >
            {isRunningAll
              ? (activeRiskFilter === "ALL" ? "⏳ Running All 30 Attacks..." : `⏳ Running All 3 ${activeRiskFilter} Scenarios...`)
              : (activeRiskFilter === "ALL" ? "⚡ Run All 30 Attacks" : `⚡ Run All 3 ${activeRiskFilter} Scenarios`)}
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
          <span className="metric-value">{activeRiskFilter === "ALL" ? 30 : filteredScenarios.length}</span>
          <span className="metric-sub">
            {activeRiskFilter === "ALL" ? "10 OWASP Risks (3 each)" : `${filteredScenarios.length} Scenarios in ${activeRiskFilter}`}
          </span>
        </div>
        <div className="metric-box">
          <span className="metric-label">STAGE</span>
          <span className="metric-value stage-tag">{selectedStage}</span>
          <span className="metric-sub">{selectedProvider.toUpperCase()}</span>
        </div>
        <div className="metric-box">
          <span className="metric-label">TESTS EXECUTED</span>
          <span className="metric-value">
            {activeRiskFilter === "ALL" ? (currentStageStats?.total || 0) : riskStats.executed}
          </span>
          <span className="metric-sub">
            {activeRiskFilter === "ALL" ? "Recorded in SQLite" : `${riskStats.executed} of ${filteredScenarios.length} executed`}
          </span>
        </div>
        <div className="metric-box">
          <span className="metric-label">DEFENSE BLOCK RATE</span>
          <span className="metric-value highlight">
            {activeRiskFilter === "ALL" ? (currentStageStats?.block_rate_percent || 0) : riskStats.blockRatePercent}%
          </span>
          <span className="metric-sub">
            {activeRiskFilter === "ALL"
              ? `${currentStageStats?.blocked || 0} Blocked / ${currentStageStats?.total || 0}`
              : `${riskStats.blocked} Blocked / ${riskStats.executed}`}
          </span>
        </div>
        <div className="metric-box counts-box">
          <span className="metric-label">OUTCOME BREAKDOWN</span>
          <div className="breakdown-pills">
            <span className="pill-blocked">
              🛡️ {activeRiskFilter === "ALL" ? (currentStageStats?.blocked || 0) : riskStats.blocked} BLOCKED
            </span>
            <span className="pill-partial">
              ⚠️ {activeRiskFilter === "ALL" ? (currentStageStats?.partial || 0) : riskStats.partial} PARTIAL
            </span>
            <span className="pill-succeeded">
              ❌ {activeRiskFilter === "ALL" ? (currentStageStats?.succeeded || 0) : riskStats.succeeded} SUCCEEDED
            </span>
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

            <button
              className="btn-batch-risk"
              onClick={() => handleRunBatch(activeRiskFilter === "ALL" ? null : activeRiskFilter)}
              disabled={isRunningAll || runningScenarioId}
            >
              {isRunningAll
                ? (activeRiskFilter === "ALL" ? "⏳ Running 30 Attacks..." : `⏳ Running ${activeRiskFilter}...`)
                : (activeRiskFilter === "ALL" ? "⚡ Run All 30 Attacks" : `▶ Run All 3 ${activeRiskFilter} Scenarios`)}
            </button>
          </div>

          {latestBatchResult && (latestBatchResult.riskId === activeRiskFilter || activeRiskFilter === "ALL" || latestBatchResult.riskId === "ALL") && (
            <div className="consolidated-result-card">
              <div className="consolidated-card-header">
                <div className="consolidated-header-left">
                  <span className="consolidated-badge-label">CONSOLIDATED BATCH RESULT</span>
                  <h4 className="consolidated-risk-heading">
                    {latestBatchResult.riskId === "ALL" ? "All 10 OWASP Risks (30 Scenarios)" : `${latestBatchResult.riskId} Assessment`}
                  </h4>
                  <span className="consolidated-meta">
                    Stage: <b>{latestBatchResult.stage}</b> · Target: <b>{latestBatchResult.provider.toUpperCase()}</b> ({latestBatchResult.model}) · Duration: <b>{latestBatchResult.durationMs}ms</b> · Completed at {latestBatchResult.executedAt}
                  </span>
                </div>
                <div className="consolidated-header-right">
                  <div className="consolidated-badges-row">
                    <span className={`status-badge ${latestBatchResult.verdictClass} large-verdict`}>
                      {latestBatchResult.verdict}
                    </span>
                    <span className={`mode-badge ${latestBatchResult.executionMode === "live" ? "badge-live" : "badge-mock"}`}>
                      {latestBatchResult.executionMode === "live" ? "🟢 LIVE API" : "🧪 MOCK MODE (SYNTHETIC)"}
                    </span>
                  </div>
                  <div className="consolidated-download-actions">
                    <button
                      className="btn-batch-download btn-download-pdf"
                      onClick={() => handleDownloadExport("pdf")}
                      disabled={isDownloadingPdf || isDownloadingCsv}
                      title="Download complete assessment report as PDF"
                    >
                      {isDownloadingPdf ? "⏳ Generating PDF..." : "📄 Download PDF"}
                    </button>
                    <button
                      className="btn-batch-download btn-download-csv"
                      onClick={() => handleDownloadExport("csv")}
                      disabled={isDownloadingPdf || isDownloadingCsv}
                      title="Download scenario results as CSV"
                    >
                      {isDownloadingCsv ? "⏳ Generating CSV..." : "📊 Download CSV"}
                    </button>
                  </div>
                </div>
              </div>

              {exportError && (
                <div className="batch-export-error">
                  ⚠️ {exportError}
                </div>
              )}

              <p className="consolidated-verdict-desc">{latestBatchResult.verdictDescription}</p>

              <div className="consolidated-metrics-grid">
                <div className="consolidated-stat-box">
                  <span className="stat-title">TOTAL SCENARIOS</span>
                  <span className="stat-num">{latestBatchResult.totalScenarios}</span>
                </div>
                <div className="consolidated-stat-box">
                  <span className="stat-title">EXECUTED</span>
                  <span className="stat-num">{latestBatchResult.executedScenarios}</span>
                </div>
                <div className="consolidated-stat-box stat-success">
                  <span className="stat-title">🛡️ BLOCKED</span>
                  <span className="stat-num highlight-green">{latestBatchResult.blockedCount}</span>
                </div>
                <div className="consolidated-stat-box stat-warning">
                  <span className="stat-title">⚠️ PARTIAL</span>
                  <span className="stat-num highlight-yellow">{latestBatchResult.partialCount}</span>
                </div>
                <div className="consolidated-stat-box stat-danger">
                  <span className="stat-title">❌ SUCCEEDED</span>
                  <span className="stat-num highlight-red">{latestBatchResult.succeededCount}</span>
                </div>
                <div className="consolidated-stat-box">
                  <span className="stat-title">DURATION</span>
                  <span className="stat-num">{latestBatchResult.durationMs}ms</span>
                </div>
              </div>
            </div>
          )}

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

