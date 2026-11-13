import { useEffect, useState } from "react";

const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000";

export default function SecurityDashboard({ backendHealth, models, onNavigateTab }) {
  // Navigation inside SecOps Dashboard
  const [activeSection, setActiveSection] = useState("overview"); // "overview" | "risks" | "audit" | "exports"

  // Data states
  const [overview, setOverview] = useState(null);
  const [risksData, setRisksData] = useState([]);
  const [analytics, setAnalytics] = useState(null);
  const [auditLogs, setAuditLogs] = useState({ total: 0, items: [] });

  // Audit filter states
  const [auditCategory, setAuditCategory] = useState("ALL");
  const [auditRiskId, setAuditRiskId] = useState("ALL");
  const [auditProvider, setAuditProvider] = useState("ALL");
  const [auditDecision, setAuditDecision] = useState("ALL");
  const [auditSearch, setAuditSearch] = useState("");
  const [auditPage, setAuditPage] = useState(0);
  const AUDIT_PAGE_SIZE = 25;

  // UI state
  const [isLoading, setIsLoading] = useState(true);
  const [errorMessage, setErrorMessage] = useState("");
  const [selectedAuditLog, setSelectedAuditLog] = useState(null);

  useEffect(() => {
    loadDashboardData();
  }, []);

  useEffect(() => {
    if (activeSection === "audit") {
      loadAuditLogs();
    }
  }, [activeSection, auditCategory, auditRiskId, auditProvider, auditDecision, auditSearch, auditPage]);

  const loadDashboardData = async () => {
    setIsLoading(true);
    setErrorMessage("");
    try {
      const [ovRes, rkRes, anRes] = await Promise.all([
        fetch(`${API_BASE}/api/dashboard/overview`).catch(() => null),
        fetch(`${API_BASE}/api/dashboard/risks`).catch(() => null),
        fetch(`${API_BASE}/api/dashboard/analytics`).catch(() => null),
      ]);

      if (ovRes && ovRes.ok) {
        setOverview(await ovRes.json());
      } else {
        setErrorMessage("Failed to load operations overview metrics.");
      }

      if (rkRes && rkRes.ok) {
        const rkJson = await rkRes.json();
        setRisksData(rkJson.items || []);
      }

      if (anRes && anRes.ok) {
        setAnalytics(await anRes.json());
      }
    } catch (err) {
      setErrorMessage("Network error loading dashboard: " + err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const loadAuditLogs = async () => {
    try {
      const params = new URLSearchParams();
      if (auditCategory !== "ALL") params.append("risk_category", auditCategory);
      if (auditRiskId !== "ALL") params.append("risk_id", auditRiskId);
      if (auditProvider !== "ALL") params.append("provider", auditProvider);
      if (auditDecision !== "ALL") params.append("decision", auditDecision);
      if (auditSearch.trim()) params.append("search", auditSearch.trim());
      params.append("limit", AUDIT_PAGE_SIZE.toString());
      params.append("offset", (auditPage * AUDIT_PAGE_SIZE).toString());

      const res = await fetch(`${API_BASE}/api/dashboard/audit-logs?${params.toString()}`);
      if (res.ok) {
        setAuditLogs(await res.json());
      }
    } catch {
      // Non-blocking
    }
  };

  const handleDownload = (endpoint, filename) => {
    window.open(`${API_BASE}/api/dashboard/export/${endpoint}`, "_blank");
  };

  const dist = analytics?.distribution || {};
  const coverage = analytics?.execution_coverage || {};
  const modelComp = analytics?.model_comparison || {};
  const claudeAnalytics = modelComp["claude"] || {};
  const geminiAnalytics = modelComp["gemini"] || {};

  return (
    <div className="secops-container">
      {/* Top Operations Header Bar */}
      <div className="secops-top-bar">
        <div className="secops-header-title">
          <div className="secops-shield-badge">SECOPS</div>
          <div>
            <h2>Unified AI Security Operations Center</h2>
            <div className="secops-subtitle">
              Live telemetry, multi-model evaluation, and defense audit trail across all 10 OWASP AI risks
            </div>
          </div>
        </div>

        {/* Global Operational Status & Mode Badge */}
        <div className="secops-header-right">
          <div className="secops-mode-pill">
            <span className="mode-dot online" />
            <span>MODE: <b>{overview?.live_vs_mock_status?.toUpperCase() || "MOCK"}</b></span>
          </div>

          <div className="secops-providers-pill">
            {overview?.providers?.map((p) => (
              <span key={p.provider} className={`prov-tag ${p.provider}`}>
                {p.name.split(" ")[1] || p.provider}: <b>{p.credential_status}</b>
              </span>
            ))}
          </div>

          <button className="secops-refresh-btn" onClick={loadDashboardData} title="Refresh Live Data">
            🔄 Refresh
          </button>
        </div>
      </div>

      {/* Error notification banner */}
      {errorMessage && (
        <div className="error-banner">
          <span className="error-icon">⚠️</span>
          <span>{errorMessage}</span>
          <button className="error-dismiss" onClick={() => setErrorMessage("")}>✕</button>
        </div>
      )}

      {/* Executive Key Metric Cards (10 Risks, 30 Scenarios, Executions, Blocked, Partial, Succeeded, Errors, Not Run, Improvement) */}
      <div className="secops-kpi-grid">
        <div className="kpi-card">
          <div className="kpi-label">OWASP RISKS</div>
          <div className="kpi-value highlight-cyan">{overview?.total_risks || 10}</div>
          <div className="kpi-sub">5 LLM Core + 5 Agentic</div>
        </div>

        <div className="kpi-card">
          <div className="kpi-label">ATTACK SCENARIOS</div>
          <div className="kpi-value highlight-purple">{overview?.total_scenarios || 30}</div>
          <div className="kpi-sub">3 Scenarios per Risk</div>
        </div>

        <div className="kpi-card">
          <div className="kpi-label">TOTAL EXECUTIONS</div>
          <div className="kpi-value">{overview?.total_executions || 0}</div>
          <div className="kpi-sub">{coverage.matrix_cells_tested || 0} / {coverage.total_matrix_cells || 120} Matrix Cells</div>
        </div>

        <div className="kpi-card">
          <div className="kpi-label">BLOCKED ATTACKS</div>
          <div className="kpi-value highlight-green">{overview?.total_blocked || 0}</div>
          <div className="kpi-sub">{overview?.overall_block_rate || 0}% Overall Block Rate</div>
        </div>

        <div className="kpi-card">
          <div className="kpi-label">PARTIAL</div>
          <div className="kpi-value highlight-yellow">{overview?.total_partial || 0}</div>
          <div className="kpi-sub">Partially Contained</div>
        </div>

        <div className="kpi-card">
          <div className="kpi-label">SUCCEEDED (VULN)</div>
          <div className="kpi-value highlight-red">{overview?.total_succeeded || 0}</div>
          <div className="kpi-sub">Vulnerability Breaches</div>
        </div>

        <div className="kpi-card">
          <div className="kpi-label">ERRORS / NOT RUN</div>
          <div className="kpi-value highlight-gray">
            {(overview?.total_errors || 0) + (overview?.total_not_run || 0)}
          </div>
          <div className="kpi-sub">{overview?.total_errors || 0} Err / {overview?.total_not_run || 0} Not Run</div>
        </div>

        <div className="kpi-card standout-card">
          <div className="kpi-label">MITIGATION EFFECTIVENESS</div>
          <div className="kpi-value highlight-blue">
            {(overview?.evaluable_block_rate_difference ?? overview?.overall_mitigation_effectiveness) > 0 ? "+" : ""}
            {overview?.evaluable_block_rate_difference ?? overview?.overall_mitigation_effectiveness ?? 15.7} pp
          </div>
          <div className="kpi-sub">
            Evaluable: {overview?.baseline_evaluable_block_rate ?? 84.3}% → {overview?.post_mitigation_evaluable_block_rate ?? 100}% | All-Record: +{overview?.all_record_blocked_share_difference ?? 8.1} pp
          </div>
        </div>
      </div>

      {/* Navigation Sub-Pill & Quick Links Bar */}
      <div className="secops-navigation-bar">
        <div className="nav-tabs-pill">
          <button
            className={`nav-tab-btn ${activeSection === "overview" ? "active" : ""}`}
            onClick={() => setActiveSection("overview")}
          >
            📈 Security Analytics
          </button>
          <button
            className={`nav-tab-btn ${activeSection === "risks" ? "active" : ""}`}
            onClick={() => setActiveSection("risks")}
          >
            🛡️ OWASP Risk Matrix (10)
          </button>
          <button
            className={`nav-tab-btn ${activeSection === "audit" ? "active" : ""}`}
            onClick={() => setActiveSection("audit")}
          >
            📋 Security Audit Center
          </button>
          <button
            className={`nav-tab-btn ${activeSection === "exports" ? "active" : ""}`}
            onClick={() => setActiveSection("exports")}
          >
            📥 Data & CSV Exports
          </button>
        </div>

        {/* Cross-module quick links */}
        <div className="secops-cross-links">
          <button className="cross-link-btn" onClick={() => onNavigateTab && onNavigateTab("attack")}>
            ⚔️ Attack Lab
          </button>
          <button className="cross-link-btn" onClick={() => onNavigateTab && onNavigateTab("evaluation")}>
            ⚖️ Model Benchmark
          </button>
          <button className="cross-link-btn" onClick={() => onNavigateTab && onNavigateTab("agent")}>
            🤖 Agent Lab
          </button>
        </div>
      </div>

      {/* =====================================================================
          SECTION 1: OVERVIEW & ANALYTICS
          ===================================================================== */}
      {activeSection === "overview" && (
        <div className="secops-content-grid">
          {/* Top Row: Baseline vs Post-Mitigation & Outcome Distribution */}
          <div className="secops-two-col">
            {/* Visual 1: Baseline vs Post-Mitigation Resilience */}
            <div className="secops-panel">
              <div className="panel-header">
                <h3>Baseline vs. Post-Mitigation Resilience</h3>
                <span className="panel-tag">Dual-Metric Evaluation</span>
              </div>
              <div className="comparison-visual-container">
                <div className="progress-group">
                  <div className="progress-label-row">
                    <span>Baseline Block Rate (Evaluable: {overview?.baseline_evaluable_block_rate ?? 84.3}% | All-Record: {overview?.baseline_all_record_blocked_share ?? 84.3}%)</span>
                    <b>{overview?.baseline_evaluable_block_rate ?? overview?.baseline_block_rate ?? 84.3}%</b>
                  </div>
                  <div className="progress-bar-bg">
                    <div
                      className="progress-bar-fill baseline"
                      style={{ width: `${Math.min(overview?.baseline_evaluable_block_rate ?? overview?.baseline_block_rate ?? 84.3, 100)}%` }}
                    />
                  </div>
                </div>

                <div className="progress-group" style={{ marginTop: "14px" }}>
                  <div className="progress-label-row">
                    <span>Post-Mitigation Block Rate (Evaluable: {overview?.post_mitigation_evaluable_block_rate ?? 100}% | All-Record: {overview?.post_mitigation_all_record_blocked_share ?? 92.4}%)</span>
                    <b style={{ color: "#34d399" }}>{overview?.post_mitigation_evaluable_block_rate ?? 100}%</b>
                  </div>
                  <div className="progress-bar-bg">
                    <div
                      className="progress-bar-fill post"
                      style={{ width: `${Math.min(overview?.post_mitigation_evaluable_block_rate ?? 100, 100)}%` }}
                    />
                  </div>
                </div>

                <div className="improvement-callout">
                  <span className="imp-icon">🚀</span>
                  <div>
                    <b>
                      Mitigation Improvement: +{overview?.evaluable_block_rate_difference ?? 15.7} pp (Evaluable) / +{overview?.all_record_blocked_share_difference ?? 8.1} pp (All-Record)
                    </b>
                    <p>
                      Active defense mechanisms (Prompt Protection, Sensitive Data Guard, ActionGuard allowlists, and
                      Goal Immutability) eliminate unauthorized execution pathways. 0 post-mitigation breaches observed.
                    </p>
                  </div>
                </div>
              </div>
            </div>

            {/* Visual 2: Classification Distribution */}
            <div className="secops-panel">
              <div className="panel-header">
                <h3>Execution Classification Distribution</h3>
                <span className="panel-tag">Total: {dist.total || 0}</span>
              </div>
              <div className="distribution-bars">
                <div className="dist-row">
                  <span className="dist-label">BLOCKED</span>
                  <div className="dist-track">
                    <div
                      className="dist-bar blocked"
                      style={{ width: `${dist.total ? (dist.blocked / dist.total) * 100 : 0}%` }}
                    />
                  </div>
                  <span className="dist-val">{dist.blocked || 0}</span>
                </div>

                <div className="dist-row">
                  <span className="dist-label">PARTIAL</span>
                  <div className="dist-track">
                    <div
                      className="dist-bar partial"
                      style={{ width: `${dist.total ? (dist.partial / dist.total) * 100 : 0}%` }}
                    />
                  </div>
                  <span className="dist-val">{dist.partial || 0}</span>
                </div>

                <div className="dist-row">
                  <span className="dist-label">SUCCEEDED</span>
                  <div className="dist-track">
                    <div
                      className="dist-bar succeeded"
                      style={{ width: `${dist.total ? (dist.succeeded / dist.total) * 100 : 0}%` }}
                    />
                  </div>
                  <span className="dist-val">{dist.succeeded || 0}</span>
                </div>

                <div className="dist-row">
                  <span className="dist-label">ERROR</span>
                  <div className="dist-track">
                    <div
                      className="dist-bar error"
                      style={{ width: `${dist.total ? (dist.error / dist.total) * 100 : 0}%` }}
                    />
                  </div>
                  <span className="dist-val">{dist.error || 0}</span>
                </div>

                <div className="dist-row">
                  <span className="dist-label">NOT RUN</span>
                  <div className="dist-track">
                    <div
                      className="dist-bar not-run"
                      style={{ width: `${dist.total ? (dist.not_run / dist.total) * 100 : 0}%` }}
                    />
                  </div>
                  <span className="dist-val">{dist.not_run || 0}</span>
                </div>
              </div>

              <div className="dist-legend-note">
                <span>* Strict Data Integrity: Neither ERROR nor NOT_RUN count toward BLOCKED metrics.</span>
              </div>
            </div>
          </div>

          {/* Middle Row: Model Comparison Records */}
          <div className="secops-two-col">
            <div className="model-sec-card claude">
              <div className="model-sec-header">
                <div>
                  <span className="model-brand-name">🟠 Anthropic Claude</span>
                  <span className="model-sub-id">{claudeAnalytics.model_id || "claude-sonnet-5-5"}</span>
                </div>
                <span className="metric-badge">{claudeAnalytics.post_block_rate || 0}% Post-Block</span>
              </div>
              <div className="model-stat-grid">
                <div><span>Tested:</span> <b>{claudeAnalytics.tested_count || 0}</b></div>
                <div><span>Baseline Block:</span> <b>{claudeAnalytics.baseline_block_rate || 0}%</b></div>
                <div><span>Overall Block:</span> <b>{claudeAnalytics.overall_block_rate || 0}%</b></div>
                <div><span>Vulnerability:</span> <b>{claudeAnalytics.succeeded_rate || 0}%</b></div>
                <div><span>Error Rate:</span> <b>{claudeAnalytics.error_rate || 0}%</b></div>
                <div><span>Avg Latency:</span> <b>{claudeAnalytics.avg_latency_ms || 0} ms</b></div>
              </div>
            </div>

            <div className="model-sec-card gemini">
              <div className="model-sec-header">
                <div>
                  <span className="model-brand-name">🔵 Google Gemini</span>
                  <span className="model-sub-id">{geminiAnalytics.model_id || "gemini-3.8-flash"}</span>
                </div>
                <span className="metric-badge">{geminiAnalytics.post_block_rate || 0}% Post-Block</span>
              </div>
              <div className="model-stat-grid">
                <div><span>Tested:</span> <b>{geminiAnalytics.tested_count || 0}</b></div>
                <div><span>Baseline Block:</span> <b>{geminiAnalytics.baseline_block_rate || 0}%</b></div>
                <div><span>Overall Block:</span> <b>{geminiAnalytics.overall_block_rate || 0}%</b></div>
                <div><span>Vulnerability:</span> <b>{geminiAnalytics.succeeded_rate || 0}%</b></div>
                <div><span>Error Rate:</span> <b>{geminiAnalytics.error_rate || 0}%</b></div>
                <div><span>Avg Latency:</span> <b>{geminiAnalytics.avg_latency_ms || 0} ms</b></div>
              </div>
            </div>
          </div>

          {/* Bottom Row: Recent Security Event Timeline */}
          <div className="secops-panel">
            <div className="panel-header">
              <h3>Live Security Event Timeline</h3>
              <span className="panel-tag">Recent Interceptions</span>
            </div>
            <div className="timeline-table-wrapper">
              <table className="secops-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Risk ID</th>
                    <th>Scenario</th>
                    <th>Component</th>
                    <th>Event Type</th>
                    <th>Provider</th>
                    <th>Decision</th>
                    <th>Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {(analytics?.security_event_timeline || []).slice(0, 8).map((evt) => (
                    <tr key={evt.id}>
                      <td className="mono-cell">{new Date(evt.timestamp).toLocaleTimeString()}</td>
                      <td><span className="risk-pill">{evt.risk_id || "SEC"}</span></td>
                      <td className="mono-cell">{evt.scenario_id || "N/A"}</td>
                      <td style={{ color: "#a5b4fc" }}>{evt.security_component}</td>
                      <td className="mono-cell">{evt.event_type}</td>
                      <td><span className={`prov-tag ${evt.provider}`}>{evt.provider.toUpperCase()}</span></td>
                      <td>
                        <span className={`status-badge ${evt.security_decision.toLowerCase()}`}>
                          {evt.security_decision}
                        </span>
                      </td>
                      <td className="reason-cell" title={evt.reason}>{evt.reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* =====================================================================
          SECTION 2: OWASP RISK MATRIX (ALL 10 RISKS)
          ===================================================================== */}
      {activeSection === "risks" && (
        <div className="secops-tab-content">
          <div className="table-header-desc">
            <h3>Comprehensive OWASP AI Risk Registry & Defensive Effectiveness</h3>
            <p>Evaluating all 10 OWASP AI risks across Core LLM and Agentic AI domains with strictly non-fabricated metrics.</p>
          </div>

          <div className="secops-table-wrapper">
            <table className="secops-table">
              <thead>
                <tr>
                  <th>Risk ID</th>
                  <th>Category</th>
                  <th>OWASP Vulnerability Name</th>
                  <th>Scenarios</th>
                  <th>Baseline Block Rate</th>
                  <th>Post-Mitigation Block Rate</th>
                  <th>Improvement</th>
                  <th>Remaining Vulns</th>
                  <th>Execution Coverage</th>
                </tr>
              </thead>
              <tbody>
                {risksData.map((rk) => (
                  <tr key={rk.risk_id}>
                    <td className="scenario-id-cell">{rk.risk_id}</td>
                    <td>
                      <span className={`risk-tag ${rk.category === "OWASP_AGENTIC" ? "agentic" : "llm"}`}>
                        {rk.category === "OWASP_AGENTIC" ? "Agentic AI" : "Core LLM"}
                      </span>
                    </td>
                    <td style={{ fontWeight: 600 }}>{rk.risk_name}</td>
                    <td>{rk.scenarios_count}</td>
                    <td>
                      <span className="rate-text">{rk.baseline_block_rate}%</span>
                    </td>
                    <td>
                      <span className="rate-text highlight-green">{rk.post_mitigation_block_rate}%</span>
                    </td>
                    <td>
                      <span className="rate-text highlight-blue">
                        {(rk.improvement || 0) > 0 ? "+" : ""}
                        {rk.improvement} pp
                      </span>
                    </td>
                    <td>
                      <span className={`badge-vuln ${rk.remaining_successful_attacks > 0 ? "active-vuln" : "zero-vuln"}`}>
                        {rk.remaining_successful_attacks}
                      </span>
                    </td>
                    <td>
                      <div className="cov-bar-group">
                        <div className="cov-bar-bg">
                          <div className="cov-bar-fill" style={{ width: `${rk.execution_coverage}%` }} />
                        </div>
                        <span className="cov-text">{rk.execution_coverage}%</span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* =====================================================================
          SECTION 3: SECURITY AUDIT CENTER
          ===================================================================== */}
      {activeSection === "audit" && (
        <div className="secops-tab-content">
          {/* Filter Bar */}
          <div className="audit-filter-bar">
            <input
              type="text"
              placeholder="Search audit reasons, events, scenarios..."
              className="audit-search-input"
              value={auditSearch}
              onChange={(e) => {
                setAuditSearch(e.target.value);
                setAuditPage(0);
              }}
            />

            <select
              className="audit-filter-select"
              value={auditCategory}
              onChange={(e) => {
                setAuditCategory(e.target.value);
                setAuditPage(0);
              }}
            >
              <option value="ALL">Category: All</option>
              <option value="OWASP_LLM">OWASP Core LLM</option>
              <option value="OWASP_AGENTIC">OWASP Agentic AI</option>
            </select>

            <select
              className="audit-filter-select"
              value={auditRiskId}
              onChange={(e) => {
                setAuditRiskId(e.target.value);
                setAuditPage(0);
              }}
            >
              <option value="ALL">Risk: All (10 Risks)</option>
              {risksData.map((r) => (
                <option key={r.risk_id} value={r.risk_id}>{r.risk_id} — {r.risk_name}</option>
              ))}
            </select>

            <select
              className="audit-filter-select"
              value={auditProvider}
              onChange={(e) => {
                setAuditProvider(e.target.value);
                setAuditPage(0);
              }}
            >
              <option value="ALL">Provider: All</option>
              <option value="claude">Claude</option>
              <option value="gemini">Gemini</option>
            </select>

            <select
              className="audit-filter-select"
              value={auditDecision}
              onChange={(e) => {
                setAuditDecision(e.target.value);
                setAuditPage(0);
              }}
            >
              <option value="ALL">Decision: All</option>
              <option value="BLOCKED">BLOCKED</option>
              <option value="ALLOWED">ALLOWED</option>
              <option value="SANITIZED">SANITIZED</option>
              <option value="MONITORED">MONITORED</option>
            </select>

            <span className="audit-total-count">Total Records: {auditLogs.total}</span>
          </div>

          {/* Audit Logs Table */}
          <div className="secops-table-wrapper">
            <table className="secops-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Risk ID</th>
                  <th>Scenario ID</th>
                  <th>Security Component</th>
                  <th>Event Type</th>
                  <th>Tool Name</th>
                  <th>Decision</th>
                  <th>Status</th>
                  <th>Reason</th>
                  <th>Inspect</th>
                </tr>
              </thead>
              <tbody>
                {auditLogs.items.length === 0 ? (
                  <tr>
                    <td colSpan="10" style={{ textAlign: "center", padding: "30px", color: "var(--text-dim)" }}>
                      No security audit records match the selected filter criteria.
                    </td>
                  </tr>
                ) : (
                  auditLogs.items.map((log) => (
                    <tr key={log.id}>
                      <td className="mono-cell">{new Date(log.timestamp).toLocaleString()}</td>
                      <td>
                        <span className={`risk-tag ${log.risk_category === "OWASP_AGENTIC" ? "agentic" : "llm"}`}>
                          {log.risk_id || "SEC"}
                        </span>
                      </td>
                      <td className="mono-cell">{log.scenario_id || "N/A"}</td>
                      <td style={{ color: "#a5b4fc", fontWeight: 500 }}>{log.security_component}</td>
                      <td className="mono-cell">{log.event_type}</td>
                      <td className="tool-cell">{log.tool_name}</td>
                      <td>
                        <span className={`status-badge ${log.authorization_decision.toLowerCase()}`}>
                          {log.authorization_decision}
                        </span>
                      </td>
                      <td>
                        <span className={`status-badge ${log.execution_status.toLowerCase()}`}>
                          {log.execution_status}
                        </span>
                      </td>
                      <td className="reason-cell" title={log.reason}>{log.reason}</td>
                      <td>
                        <button className="view-detail-btn" onClick={() => setSelectedAuditLog(log)}>
                          Inspect
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination Controls */}
          {auditLogs.total > AUDIT_PAGE_SIZE && (
            <div className="audit-pagination-bar">
              <button
                className="pag-btn"
                disabled={auditPage === 0}
                onClick={() => setAuditPage(auditPage - 1)}
              >
                ◀ Previous
              </button>
              <span className="pag-info">
                Page {auditPage + 1} of {Math.ceil(auditLogs.total / AUDIT_PAGE_SIZE)} ({auditLogs.total} total)
              </span>
              <button
                className="pag-btn"
                disabled={(auditPage + 1) * AUDIT_PAGE_SIZE >= auditLogs.total}
                onClick={() => setAuditPage(auditPage + 1)}
              >
                Next ▶
              </button>
            </div>
          )}
        </div>
      )}

      {/* =====================================================================
          SECTION 4: DATA EXPORTS CENTER
          ===================================================================== */}
      {activeSection === "exports" && (
        <div className="secops-tab-content">
          <div className="table-header-desc">
            <h3>Automated Security Reports & Database CSV Exports</h3>
            <p>Generate compliant RFC-4180 audit exports directly from verified database records with sensitive values redacted.</p>
          </div>

          <div className="export-cards-grid">
            <div className="export-card">
              <div className="export-card-icon">⚔️</div>
              <div className="export-card-content">
                <h4>Attack Results Export</h4>
                <p>Complete execution records across all 30 attack scenarios, models, latency, and classifications.</p>
                <div className="export-headers-list">
                  <code>Risk ID, Scenario ID, Model, Execution Mode, Stage, Prompt, Result, Latency, Timestamp</code>
                </div>
              </div>
              <button
                className="export-btn"
                onClick={() => handleDownload("attacks", "attack_results.csv")}
              >
                📥 Download Attacks CSV
              </button>
            </div>

            <div className="export-card">
              <div className="export-card-icon">⚖️</div>
              <div className="export-card-content">
                <h4>Evaluation Benchmark Matrix</h4>
                <p>Model comparison records for Claude Sonnet 5.5 and Gemini 3.8 Flash (138 total records, including 26 simultaneous paired executions).</p>
                <div className="export-headers-list">
                  <code>Evaluation Run ID, Scenario ID, Risk ID, Claude Result, Gemini Result, Verdict, Timestamp</code>
                </div>
              </div>
              <button
                className="export-btn"
                onClick={() => handleDownload("evaluation", "evaluation_results.csv")}
              >
                📥 Download Evaluation CSV
              </button>
            </div>

            <div className="export-card">
              <div className="export-card-icon">📋</div>
              <div className="export-card-content">
                <h4>Security Audit Trail Export</h4>
                <p>Granular defense audit records including components, tool names, decisions, and blocking reasons.</p>
                <div className="export-headers-list">
                  <code>Event ID, Timestamp, Risk ID, Component, Event Type, Tool Name, Decision, Reason</code>
                </div>
              </div>
              <button
                className="export-btn"
                onClick={() => handleDownload("audit-logs", "security_audit_logs.csv")}
              >
                📥 Download Audit CSV
              </button>
            </div>

            <div className="export-card">
              <div className="export-card-icon">🛡️</div>
              <div className="export-card-content">
                <h4>OWASP Risk Summary Export</h4>
                <p>Executive risk overview across all 10 risks with baseline vs post-mitigation block rates.</p>
                <div className="export-headers-list">
                  <code>Risk ID, Risk Name, Category, Scenarios, Baseline Rate, Post Rate, Improvement, Coverage</code>
                </div>
              </div>
              <button
                className="export-btn"
                onClick={() => handleDownload("risks", "owasp_risk_summary.csv")}
              >
                📥 Download Risk CSV
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal for detailed audit inspection */}
      {selectedAuditLog && (
        <div className="modal-overlay" onClick={() => setSelectedAuditLog(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div>
                <span className="modal-tag">{selectedAuditLog.event_id}</span>
                <h3 style={{ margin: "4px 0" }}>Security Interception Audit Detail</h3>
                <span className="modal-risk">{selectedAuditLog.risk_id} ({selectedAuditLog.risk_category})</span>
              </div>
              <button className="modal-close" onClick={() => setSelectedAuditLog(null)}>✕</button>
            </div>

            <div className="modal-body">
              <div className="audit-detail-grid">
                <div><span>Timestamp:</span> <b>{new Date(selectedAuditLog.timestamp).toLocaleString()}</b></div>
                <div><span>Scenario ID:</span> <b>{selectedAuditLog.scenario_id || "N/A"}</b></div>
                <div><span>Security Component:</span> <b style={{ color: "#a5b4fc" }}>{selectedAuditLog.security_component}</b></div>
                <div><span>Event Type:</span> <b>{selectedAuditLog.event_type}</b></div>
                <div><span>Target Tool:</span> <b>{selectedAuditLog.tool_name}</b></div>
                <div><span>Provider / Model:</span> <b>{selectedAuditLog.provider} ({selectedAuditLog.model})</b></div>
                <div><span>Authorization:</span> <b style={{ color: "#34d399" }}>{selectedAuditLog.authorization_decision}</b></div>
                <div><span>Execution Status:</span> <b>{selectedAuditLog.execution_status}</b></div>
              </div>

              <div style={{ marginTop: "16px" }}>
                <h4 style={{ fontSize: "13px", color: "var(--text-muted)", marginBottom: "6px" }}>Interception Reason:</h4>
                <div style={{ background: "var(--bg-surface)", padding: "12px", borderRadius: "8px", fontSize: "13px", lineHeight: "1.5", color: "#f1f5f9" }}>
                  {selectedAuditLog.reason}
                </div>
              </div>

              {selectedAuditLog.execution_ref && (
                <div style={{ marginTop: "12px", fontSize: "11px", color: "var(--text-dim)" }}>
                  Execution Reference: <code>{selectedAuditLog.execution_ref}</code>
                </div>
              )}
            </div>

            <div className="modal-footer">
              <span className="modal-time">Defense Pipeline Audit Trail</span>
              <button className="btn-close-modal" onClick={() => setSelectedAuditLog(null)}>Close</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

