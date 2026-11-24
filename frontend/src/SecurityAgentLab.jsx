import { useEffect, useState } from "react";

const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000";

const QUICK_SECURITY_COMMANDS = [
  {
    label: "Autonomous OWASP Assessment (LLM01, LLM02, ASI01, ASI02)",
    command: "Test my application for OWASP risks LLM01, LLM02, ASI01 and ASI02.",
    description: "Autonomous end-to-end audit: extracts risks, plans scenarios, executes with wire trace, confirms resilience, and provides code remediations.",
  },
  {
    label: "Audit LLM01 & LLM02",
    command: "Test my application for LLM01 and LLM02.",
    description: "Evaluates prompt injection and canary disclosure across baseline and adaptive mutations.",
  },
  {
    label: "Probe Port 8000 Injection",
    command: "Run prompt injection tests against http://127.0.0.1:8000.",
    description: "Dispatches multi-turn prompt injection payloads with delimiter framing and roleplay mutations.",
  },
  {
    label: "Audit ASI01 & ASI02 Agents",
    command: "Audit ASI01 and ASI02 against my local test application.",
    description: "Probes goal hijacking, task redirection, unapproved tool usage, and sandbox traversal.",
  },
  {
    label: "Multi-Risk Attack Chain",
    command: "Evaluate my application for prompt injection and tool misuse.",
    description: "Multi-stage sequential escalation exploring whether LLM01 unlocks ASI01 and ASI02 with HMAC signatures.",
  },
  {
    label: "Full Priority OWASP Suite",
    command: "Perform an adaptive security assessment of LLM01, LLM02, ASI01, and ASI02.",
    description: "Comprehensive multi-turn audit with automated payload mutation and cryptographic SHA-256 evidence.",
  },
  {
    label: "🛡️ Claude Code Configuration Audit",
    command: "Audit Claude Code project configuration for instruction poisoning (ASI06), secret exposure (LLM08), and bash tool misuse (ASI02).",
    description: "Evaluates CLAUDE.md, settings.json, settings.local.json, and agent definitions in an isolated sandbox with dynamic hook verification.",
    tabTarget: "claude_code",
  },
];

const DEFAULT_RISKS = [
  { risk_id: "LLM01", risk_name: "Prompt Injection", category: "OWASP_LLM", severity: "CRITICAL" },
  { risk_id: "LLM02", risk_name: "Sensitive Information Disclosure", category: "OWASP_LLM", severity: "HIGH" },
  { risk_id: "ASI01", risk_name: "Agent Goal Hijacking", category: "OWASP_AGENTIC", severity: "HIGH" },
  { risk_id: "ASI02", risk_name: "Tool Misuse & Sandbox Traversal", category: "OWASP_AGENTIC", severity: "HIGH" },
  { risk_id: "LLM03", risk_name: "Supply Chain Vulnerabilities", category: "OWASP_LLM", severity: "HIGH" },
  { risk_id: "LLM04", risk_name: "Data and Model Poisoning", category: "OWASP_LLM", severity: "CRITICAL" },
  { risk_id: "ASI03", risk_name: "Agent Identity Spoofing", category: "OWASP_AGENTIC", severity: "HIGH" },
  { risk_id: "ASI05", risk_name: "Unexpected Code Execution", category: "OWASP_AGENTIC", severity: "CRITICAL" },
];

export default function SecurityAgentLab({ backendHealth }) {
  // Command & Input Configuration
  const [command, setCommand] = useState("Test my application for LLM01 and LLM02.");
  const [targetUrl, setTargetUrl] = useState("http://127.0.0.1:8000");
  const [stage, setStage] = useState("POST_MITIGATION");
  const [maxTurns, setMaxTurns] = useState(3);
  const [userAuthorized, setUserAuthorized] = useState(true);
  const [selectedRisks, setSelectedRisks] = useState(["LLM01", "LLM02", "ASI01", "ASI02"]);

  // System Metadata
  const [risksList, setRisksList] = useState(DEFAULT_RISKS);
  const [targetValidation, setTargetValidation] = useState(null);

  // Execution State (Phase B & C)
  const [isExecuting, setIsExecuting] = useState(false);
  const [activePlan, setActivePlan] = useState(null);
  const [chains, setChains] = useState([]);
  const [mutations, setMutations] = useState([]);
  const [report, setReport] = useState(null);
  const [errorMessage, setErrorMessage] = useState("");
  const [statusMessage, setStatusMessage] = useState("");

  // Autonomous Natural-Language Workflow States
  const [interpretationPreview, setInterpretationPreview] = useState(null);
  const [isInterpreting, setIsInterpreting] = useState(false);
  const [remediationsMap, setRemediationsMap] = useState({});
  const [expandedMitigationRisk, setExpandedMitigationRisk] = useState(null);
  const [downloadingFormat, setDownloadingFormat] = useState(null);
  const [copiedCodeSnippet, setCopiedCodeSnippet] = useState(null);

  // Detailed Inspectors
  const [activeTab, setActiveTab] = useState("soc_overview"); // "soc_overview" | 8 Enterprise Views | Probing Labs
  const [selectedExecutionId, setSelectedExecutionId] = useState(null);
  const [evidenceData, setEvidenceData] = useState(null);
  const [evidenceVerifying, setEvidenceVerifying] = useState(false);
  const [evidenceIntegrity, setEvidenceIntegrity] = useState(null);

  // Phase D States
  // 1. Application Context Intelligence
  const [discoveredContext, setDiscoveredContext] = useState(null);
  const [isDiscoveringContext, setIsDiscoveringContext] = useState(false);
  const [openApiSpecText, setOpenApiSpecText] = useState("");
  const [showOpenApiModal, setShowOpenApiModal] = useState(false);

  // 2. OWASP Risk Correlation
  const [correlationGraph, setCorrelationGraph] = useState(null);
  const [isFetchingCorrelation, setIsFetchingCorrelation] = useState(false);
  const [selectedCorrelationRisk, setSelectedCorrelationRisk] = useState("LLM01");

  // 3. Attack Chains
  const [attackChain, setAttackChain] = useState(null);
  const [isGeneratingChain, setIsGeneratingChain] = useState(false);
  const [isExecutingChain, setIsExecutingChain] = useState(false);
  const [chainCommand, setChainCommand] = useState("Evaluate my application for prompt injection and tool misuse");
  const [chainStage, setChainStage] = useState("POST_MITIGATION");
  const [chainRisks, setChainRisks] = useState(["LLM01", "ASI01", "ASI02"]);

  // 4. Root Cause Analysis & Remediation
  const [rcaFinding, setRcaFinding] = useState(null);
  const [rcaLoading, setRcaLoading] = useState(false);
  const [selectedRcaScenario, setSelectedRcaScenario] = useState("LLM01-01");
  const [selectedRcaRisk, setSelectedRcaRisk] = useState("LLM01");
  const [selectedRcaVerdict, setSelectedRcaVerdict] = useState("VULNERABLE");
  const [remediationDirective, setRemediationDirective] = useState(null);
  const [remediationLoading, setRemediationLoading] = useState(false);
  const [copyCodeSuccess, setCopyCodeSuccess] = useState(false);

  // Phase E1 States: Dynamic Security Intelligence
  const [intelligenceOverview, setIntelligenceOverview] = useState(null);
  const [intelligencePriorities, setIntelligencePriorities] = useState([]);
  const [intelligenceHistory, setIntelligenceHistory] = useState([]);
  const [intelligenceLoading, setIntelligenceLoading] = useState(false);
  const [intelAppId, setIntelAppId] = useState("default");
  const [intelVersion, setIntelVersion] = useState("v1.0");
  const [intelEnv, setIntelEnv] = useState("sandbox");
  const [intelEndpoint, setIntelEndpoint] = useState("/api/chat");
  const [selectedIntelRisk, setSelectedIntelRisk] = useState(null);

  // Phase E2 States: Advanced Attack Graph Planning Engine
  const [attackGraphData, setAttackGraphData] = useState(null);
  const [candidatePathsData, setCandidatePathsData] = useState(null);
  const [isAnalyzingGraph, setIsAnalyzingGraph] = useState(false);
  const [isGeneratingPaths, setIsGeneratingPaths] = useState(false);
  const [selectedPathId, setSelectedPathId] = useState(null);
  const [selectedSccId, setSelectedSccId] = useState(null);
  const [graphAppId, setGraphAppId] = useState("default");
  const [graphVersion, setGraphVersion] = useState("v1.0");
  const [graphEnv, setGraphEnv] = useState("sandbox");
  const [graphEndpoint, setGraphEndpoint] = useState("/api/chat");

  // Phase E3 States: Deep OpenAPI Schema Intelligence
  const [schemaAnalysisData, setSchemaAnalysisData] = useState(null);
  const [schemaTestPlansData, setSchemaTestPlansData] = useState(null);
  const [isAnalyzingSchema, setIsAnalyzingSchema] = useState(false);
  const [isGeneratingSchemaTests, setIsGeneratingSchemaTests] = useState(false);
  const [selectedSchemaEndpoint, setSelectedSchemaEndpoint] = useState(null);
  const [schemaFilterRisk, setSchemaFilterRisk] = useState("ALL");
  const [customSpecModal, setCustomSpecModal] = useState(false);
  const [customSpecText, setCustomSpecText] = useState("");
  const [selectedTestPlanId, setSelectedTestPlanId] = useState(null);

  // Phase E4 States: Vulnerability & Evidence Lifecycle
  const [lifecycleBoard, setLifecycleBoard] = useState(null);
  const [isFetchingLifecycle, setIsFetchingLifecycle] = useState(false);
  const [selectedLifecycleFinding, setSelectedLifecycleFinding] = useState(null);
  const [lifecycleTransitionTarget, setLifecycleTransitionTarget] = useState("");
  const [lifecycleTransitionReason, setLifecycleTransitionReason] = useState("");
  const [lifecycleTransitionEvidence, setLifecycleTransitionEvidence] = useState("");
  const [lifecycleIsSecondaryConfirmed, setLifecycleIsSecondaryConfirmed] = useState(false);
  const [isExecutingTransition, setIsExecutingTransition] = useState(false);

  // Phase E5 States: Security Regression Intelligence
  const [regressionBaselinePlanId, setRegressionBaselinePlanId] = useState("");
  const [regressionCurrentPlanId, setRegressionCurrentPlanId] = useState("");
  const [regressionComparison, setRegressionComparison] = useState(null);
  const [isComparingRegression, setIsComparingRegression] = useState(false);
  const [regressionHistory, setRegressionHistory] = useState([]);
  const [isFetchingRegressionHistory, setIsFetchingRegressionHistory] = useState(false);
  const [regressionFilter, setRegressionFilter] = useState("ALL");
  const [regressionAllowCrossTarget, setRegressionAllowCrossTarget] = useState(false);
  const [regressionAllowCrossEnv, setRegressionAllowCrossEnv] = useState(false);

  // Phase E6 States: Enterprise Reporting Engine
  const [enterpriseReportsList, setEnterpriseReportsList] = useState([]);
  const [selectedEnterpriseReport, setSelectedEnterpriseReport] = useState(null);
  const [isGeneratingEnterpriseReport, setIsGeneratingEnterpriseReport] = useState(false);
  const [isFetchingEnterpriseReports, setIsFetchingEnterpriseReports] = useState(false);
  const [reportTypeSelection, setReportTypeSelection] = useState("FULL_TECHNICAL");
  const [reportLeadAuditor, setReportLeadAuditor] = useState("ApexShield Security Engine");
  const [reportFormatPdf, setReportFormatPdf] = useState(true);
  const [reportFormatXlsx, setReportFormatXlsx] = useState(true);
  const [reportFormatCsv, setReportFormatCsv] = useState(true);
  const [reportFormatJson, setReportFormatJson] = useState(true);
  const [reportSessionIdInput, setReportSessionIdInput] = useState("");
  const [reportPlanIdInput, setReportPlanIdInput] = useState("");
  const [reportVerificationResult, setReportVerificationResult] = useState(null);
  const [isVerifyingEnterpriseReport, setIsVerifyingEnterpriseReport] = useState(false);
  const [reportActiveSection, setReportActiveSection] = useState("s1");

  // Phase E7 States: Explainability Engine
  const [decisionsList, setDecisionsList] = useState([]);
  const [decisionFilterType, setDecisionFilterType] = useState("");
  const [selectedDecision, setSelectedDecision] = useState(null);
  const [isFetchingDecisions, setIsFetchingDecisions] = useState(false);

  // Phase E8 States: Operations Monitoring & Telemetry
  const [operationsOverview, setOperationsOverview] = useState(null);
  const [operationsHealth, setOperationsHealth] = useState(null);
  const [hmacAuditData, setHmacAuditData] = useState(null);
  const [circuitBreakers, setCircuitBreakers] = useState([]);
  const [isFetchingOperations, setIsFetchingOperations] = useState(false);
  const [opsAdminToken, setOpsAdminToken] = useState("apexshield_ops_admin_2026");
  const [opsResetSessionId, setOpsResetSessionId] = useState("");
  const [opsActionFeedback, setOpsActionFeedback] = useState(null);

  // Phase E9 States: Enterprise Security Operations Center (SOC) & Shared Context
  const [socOverviewData, setSocOverviewData] = useState(null);
  const [isFetchingSocOverview, setIsFetchingSocOverview] = useState(false);
  const [sharedSessionFilter, setSharedSessionFilter] = useState("");
  const [sharedPlanFilter, setSharedPlanFilter] = useState("");
  const [sharedFindingFilter, setSharedFindingFilter] = useState("");

  // Claude Code Configuration Security Assessment States
  const [claudeCodeFiles, setClaudeCodeFiles] = useState({
    claude_md: "",
    settings_json: "",
    settings_local_json: "",
    report_writer_md: "",
  });
  const [claudeCodeActiveFileTab, setClaudeCodeActiveFileTab] = useState("claude_md");
  const [isEvaluatingClaudeCode, setIsEvaluatingClaudeCode] = useState(false);
  const [isLoadingClaudeSample, setIsLoadingClaudeSample] = useState(false);
  const [claudeCodeResult, setClaudeCodeResult] = useState(null);
  const [claudeCodeExporting, setClaudeCodeExporting] = useState(null);
  const [claudeCodeError, setClaudeCodeError] = useState(null);
  const [copiedRemediationId, setCopiedRemediationId] = useState(null);

  // Fetch risks list on mount
  useEffect(() => {
    fetch(`${API_BASE}/api/security-agent/risks`)
      .then((res) => (res.ok ? res.json() : []))
      .then((data) => {
        if (data && data.length > 0) setRisksList(data);
      })
      .catch(() => {});
  }, []);

  // Validate target when URL changes
  useEffect(() => {
    if (!targetUrl) return;
    const timer = setTimeout(() => {
      fetch(`${API_BASE}/api/security-agent/validate-target`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_url: targetUrl,
          user_confirmed_authorization: userAuthorized,
        }),
      })
        .then((res) => (res.ok ? res.json() : null))
        .then((data) => {
          if (data) setTargetValidation(data);
        })
        .catch(() => {});
    }, 400);
    return () => clearTimeout(timer);
  }, [targetUrl, userAuthorized]);

  // Live command interpretation & risk synchronization
  useEffect(() => {
    if (!command || !command.trim()) {
      setInterpretationPreview(null);
      return;
    }
    const timer = setTimeout(async () => {
      setIsInterpreting(true);
      try {
        const res = await fetch(`${API_BASE}/api/security-agent/interpret`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ command: command.trim() }),
        });
        if (res.ok) {
          const data = await res.json();
          setInterpretationPreview(data);
          // Auto-sync risk selection pills if specific risks are identified
          if (data.identified_risks && data.identified_risks.length > 0) {
            const riskIds = data.identified_risks.map((r) => r.risk_id);
            setSelectedRisks(riskIds);
          }
        }
      } catch (err) {
        console.error("Command interpretation preview error:", err);
      } finally {
        setIsInterpreting(false);
      }
    }, 350);
    return () => clearTimeout(timer);
  }, [command]);

  const toggleRisk = (riskId) => {
    setSelectedRisks((prev) =>
      prev.includes(riskId) ? prev.filter((r) => r !== riskId) : [...prev, riskId]
    );
  };

  const toggleChainRisk = (riskId) => {
    setChainRisks((prev) =>
      prev.includes(riskId) ? prev.filter((r) => r !== riskId) : [...prev, riskId]
    );
  };

  // Launch Adaptive Multi-Turn Execution
  const handleExecuteAdaptivePlan = async () => {
    if (isExecuting) return;

    // Check if command has blocking reasons (e.g. invalid risk codes like LLM99)
    if (interpretationPreview?.blocking_reasons && interpretationPreview.blocking_reasons.length > 0) {
      setErrorMessage(interpretationPreview.blocking_reasons[0]);
      return;
    }

    setErrorMessage("");
    setStatusMessage("Interpreting security command and generating execution plan...");
    setIsExecuting(true);
    setActivePlan(null);
    setChains([]);
    setMutations([]);
    setReport(null);
    setRemediationsMap({});
    setSelectedExecutionId(null);
    setEvidenceData(null);
    setEvidenceIntegrity(null);

    try {
      const payload = {
        command: command.trim() || undefined,
        target_url: targetUrl,
        stage: stage,
        risk_ids: selectedRisks.length > 0 ? selectedRisks : undefined,
        max_turns: Number(maxTurns),
        user_confirmed_authorization: userAuthorized,
      };

      const res = await fetch(`${API_BASE}/api/security-agent/plans/adaptive`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }));
        throw new Error(err.detail || `Adaptive execution failed (HTTP ${res.status})`);
      }

      const planSummary = await res.json();
      setActivePlan(planSummary);
      setStatusMessage(`Completed execution for plan ${planSummary.plan_id.slice(0, 8)}.`);

      // Fetch chains, mutations, assessment report, and actionable mitigations
      await Promise.all([
        fetchPlanDetails(planSummary.plan_id),
        fetchPlanRemediations(planSummary),
      ]);
    } catch (err) {
      setErrorMessage(err.message || "Failed to execute adaptive testing plan.");
    } finally {
      setIsExecuting(false);
    }
  };

  // Fetch automated actionable mitigations for assessed risks
  const fetchPlanRemediations = async (planSummary) => {
    if (!planSummary) return;
    const risksToFetch = new Set();
    if (planSummary.risk_assessments) {
      Object.keys(planSummary.risk_assessments).forEach((r) => risksToFetch.add(r));
    }
    if (planSummary.scenario_summaries) {
      planSummary.scenario_summaries.forEach((s) => {
        if (s.risk_code) risksToFetch.add(s.risk_code);
      });
    }
    if (risksToFetch.size === 0 && selectedRisks.length > 0) {
      selectedRisks.forEach((r) => risksToFetch.add(r));
    }

    const fetched = {};
    for (const r of risksToFetch) {
      try {
        const res = await fetch(`${API_BASE}/api/security-agent/remediation/finding_${r}?risk_id=${r}`);
        if (res.ok) {
          const data = await res.json();
          fetched[r] = data;
        }
      } catch (e) {
        console.error(`Failed to fetch remediation for ${r}:`, e);
      }
    }
    setRemediationsMap(fetched);
    const riskList = Array.from(risksToFetch);
    if (riskList.length > 0) {
      setExpandedMitigationRisk(riskList[0]);
    }
  };

  // Direct 1-click report download handler (PDF, XLSX, CSV, JSON)
  const handleDownloadAutonomousReport = async (format) => {
    if (!activePlan) return;
    setDownloadingFormat(format);
    try {
      let downloadUrl = activePlan.download_urls?.[format];
      if (!downloadUrl && activePlan.report_id) {
        downloadUrl = `/api/security-agent/reports/${activePlan.report_id}/download/${format}`;
      }
      if (!downloadUrl) {
        // Fallback: trigger enterprise report generation on-the-fly
        const genRes = await fetch(`${API_BASE}/api/security-agent/reports/enterprise`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            plan_id: activePlan.plan_id,
            session_id: activePlan.session_id,
            report_type: "FULL_TECHNICAL",
            formats: [format],
          }),
        });
        if (genRes.ok) {
          const genData = await genRes.json();
          downloadUrl = genData.download_urls?.[format] || `/api/security-agent/reports/${genData.report_id}/download/${format}`;
        }
      }

      if (downloadUrl) {
        const fullUrl = downloadUrl.startsWith("http") ? downloadUrl : `${API_BASE}${downloadUrl}`;
        const response = await fetch(fullUrl);
        if (!response.ok) {
          throw new Error(`Download failed with status ${response.status}`);
        }
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        const ext = format === "excel" ? "xlsx" : format;
        a.download = `ApexShield_Autonomous_Assessment_${activePlan.plan_id.slice(0, 8)}.${ext}`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      } else {
        throw new Error("No download URL available for this format.");
      }
    } catch (err) {
      setErrorMessage(`Report download failed: ${err.message}`);
    } finally {
      setDownloadingFormat(null);
    }
  };

  // Cancel execution
  const handleCancelExecution = async () => {
    if (!activePlan?.plan_id) return;
    try {
      setStatusMessage("Cancelling in-progress execution...");
      const res = await fetch(`${API_BASE}/api/security-agent/plans/${activePlan.plan_id}/cancel`, {
        method: "POST",
      });
      if (res.ok) {
        setStatusMessage("Execution successfully cancelled.");
        setIsExecuting(false);
        fetchPlanDetails(activePlan.plan_id);
      }
    } catch {
      setErrorMessage("Network error while attempting cancellation.");
    }
  };

  const fetchPlanDetails = async (planId) => {
    try {
      const [chainsRes, mutRes, reportRes] = await Promise.all([
        fetch(`${API_BASE}/api/security-agent/plans/${planId}/chains`).catch(() => null),
        fetch(`${API_BASE}/api/security-agent/plans/${planId}/mutations`).catch(() => null),
        fetch(`${API_BASE}/api/security-agent/plans/${planId}/report`).catch(() => null),
      ]);

      if (chainsRes && chainsRes.ok) {
        const chainsData = await chainsRes.json();
        setChains(chainsData);
        if (chainsData.length > 0 && chainsData[0].turns?.length > 0) {
          inspectExecution(chainsData[0].turns[0].execution_id);
        }
      }

      if (mutRes && mutRes.ok) {
        const mutData = await mutRes.json();
        setMutations(mutData);
      }

      if (reportRes && reportRes.ok) {
        const reportData = await reportRes.json();
        setReport(reportData);
      }
    } catch {
      // Non-blocking
    }
  };

  // Load individual execution wire evidence
  const inspectExecution = async (executionId) => {
    setSelectedExecutionId(executionId);
    setEvidenceData(null);
    setEvidenceIntegrity(null);
    try {
      const res = await fetch(`${API_BASE}/api/security-agent/executions/${executionId}/evidence`);
      if (res.ok) {
        const data = await res.json();
        setEvidenceData(data);
      }
    } catch {
      // Non-blocking
    }
  };

  // Cryptographic integrity verification
  const handleVerifyIntegrity = async (executionId) => {
    if (!executionId || evidenceVerifying) return;
    setEvidenceVerifying(true);
    try {
      const res = await fetch(`${API_BASE}/api/security-agent/executions/${executionId}/verify-integrity`, {
        method: "POST",
      });
      if (res.ok) {
        const data = await res.json();
        setEvidenceIntegrity(data);
      }
    } catch {
      setEvidenceIntegrity({ is_verified: false, match: false, error: "Network error during verification." });
    } finally {
      setEvidenceVerifying(false);
    }
  };

  // =====================================================================
  // Phase D: Handlers
  // =====================================================================

  // 1. Application Context Discovery
  const handleDiscoverContext = async () => {
    setIsDiscoveringContext(true);
    setErrorMessage("");
    setStatusMessage("Performing controlled reconnaissance on target application...");
    try {
      const res = await fetch(`${API_BASE}/api/security-agent/context/discover`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_url: targetUrl,
          user_confirmed_authorization: userAuthorized,
        }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }));
        throw new Error(err.detail || "Failed to discover target context");
      }
      const data = await res.json();
      setDiscoveredContext(data);
      setStatusMessage(`Reconnaissance complete: ${data.discovered_endpoints.length} endpoints identified.`);
    } catch (err) {
      setErrorMessage(err.message || "Failed to discover application context.");
    } finally {
      setIsDiscoveringContext(false);
    }
  };

  const handleImportOpenApi = async () => {
    if (!openApiSpecText.trim()) return;
    setIsDiscoveringContext(true);
    setErrorMessage("");
    try {
      let parsedSpec;
      try {
        parsedSpec = JSON.parse(openApiSpecText);
      } catch {
        throw new Error("Invalid JSON format in OpenAPI specification.");
      }

      const res = await fetch(`${API_BASE}/api/security-agent/context/import-openapi`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_url: targetUrl,
          openapi_spec: parsedSpec,
          user_confirmed_authorization: userAuthorized,
        }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }));
        throw new Error(err.detail || "Failed to parse OpenAPI spec");
      }

      const data = await res.json();
      setDiscoveredContext(data);
      setShowOpenApiModal(false);
      setStatusMessage(`OpenAPI imported: ${data.discovered_endpoints.length} endpoints parsed.`);
    } catch (err) {
      setErrorMessage(err.message || "Failed to import OpenAPI specification.");
    } finally {
      setIsDiscoveringContext(false);
    }
  };

  // 2. Risk Correlation Graph
  const handleFetchCorrelationGraph = async () => {
    setIsFetchingCorrelation(true);
    try {
      const res = await fetch(`${API_BASE}/api/security-agent/correlation/graph`);
      if (res.ok) {
        const data = await res.json();
        setCorrelationGraph(data);
      }
    } catch {
      // Non-blocking
    } finally {
      setIsFetchingCorrelation(false);
    }
  };

  useEffect(() => {
    if (activeTab === "correlation" && !correlationGraph) {
      handleFetchCorrelationGraph();
    }
  }, [activeTab]);

  // 3. Multi-Risk Attack Chains
  const handleGenerateAttackChain = async () => {
    setIsGeneratingChain(true);
    setErrorMessage("");
    setStatusMessage("Synthesizing multi-stage sequential attack chain...");
    try {
      const res = await fetch(`${API_BASE}/api/security-agent/attack-chains/generate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          command: chainCommand.trim() || undefined,
          target_url: targetUrl,
          stage: chainStage,
          risk_ids: chainRisks.length > 0 ? chainRisks : undefined,
          user_confirmed_authorization: userAuthorized,
        }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }));
        throw new Error(err.detail || "Failed to generate attack chain");
      }

      const data = await res.json();
      setAttackChain(data);
      setStatusMessage(`Attack chain generated: ${data.chain_name} (${data.execution_steps.length} steps).`);
    } catch (err) {
      setErrorMessage(err.message || "Failed to generate attack chain.");
    } finally {
      setIsGeneratingChain(false);
    }
  };

  const handleExecuteAttackChain = async () => {
    if (!attackChain?.chain_id || isExecutingChain) return;
    setIsExecutingChain(true);
    setErrorMessage("");
    setStatusMessage(`Executing attack chain ${attackChain.chain_id} with wire HMAC signing...`);
    try {
      const res = await fetch(
        `${API_BASE}/api/security-agent/attack-chains/${attackChain.chain_id}/execute?target_url=${encodeURIComponent(targetUrl)}`,
        { method: "POST" }
      );

      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }));
        throw new Error(err.detail || "Failed to execute attack chain");
      }

      const data = await res.json();
      setAttackChain(data);
      setStatusMessage(`Attack chain execution complete: ${data.final_assessment}`);
    } catch (err) {
      setErrorMessage(err.message || "Failed to execute attack chain.");
    } finally {
      setIsExecutingChain(false);
    }
  };

  // 4. Root Cause Analysis & Remediation
  const handleRunRca = async () => {
    setRcaLoading(true);
    setErrorMessage("");
    try {
      const res = await fetch(`${API_BASE}/api/security-agent/rca/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scenario_id: selectedRcaScenario,
          risk_id: selectedRcaRisk,
          endpoint: "/api/chat",
          verdict: selectedRcaVerdict,
          status_code: selectedRcaVerdict === "VULNERABLE" ? 200 : 403,
          response_body: selectedRcaVerdict === "VULNERABLE" ? "CONFIDENTIAL_TEST_PROJECT_ALPHA leaked" : "Refused",
          is_multi_turn_confirmed: selectedRcaVerdict === "VULNERABLE",
          turn_number: 2,
        }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }));
        throw new Error(err.detail || "Failed to compute Root Cause Analysis");
      }

      const data = await res.json();
      setRcaFinding(data);

      // Also auto-fetch remediation directive
      handleFetchRemediation(data.risk_id, data.finding_id);
    } catch (err) {
      setErrorMessage(err.message || "Failed to compute Root Cause Analysis.");
    } finally {
      setRcaLoading(false);
    }
  };

  const handleFetchRemediation = async (riskId, findingId = "find_default") => {
    setRemediationLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/security-agent/remediation/${findingId}?risk_id=${riskId}`);
      if (res.ok) {
        const data = await res.json();
        setRemediationDirective(data);
      }
    } catch {
      // Non-blocking
    } finally {
      setRemediationLoading(false);
    }
  };

  const handleCopyCode = (text) => {
    navigator.clipboard?.writeText(text);
    setCopyCodeSuccess(true);
    setTimeout(() => setCopyCodeSuccess(false), 2000);
  };

  // Phase E1 Handler: Dynamic Security Intelligence
  const handleFetchIntelligence = async () => {
    setIntelligenceLoading(true);
    setErrorMessage("");
    try {
      const queryParams = new URLSearchParams({
        target_url: targetUrl || "http://127.0.0.1:8000",
        application_id: intelAppId || "default",
        app_version: intelVersion || "v1.0",
        environment: intelEnv || "sandbox",
        endpoint: intelEndpoint || "/api/chat",
      });

      const [resOverview, resPriorities, resHistory] = await Promise.all([
        fetch(`${API_BASE}/api/security-agent/intelligence/overview?${queryParams.toString()}`),
        fetch(`${API_BASE}/api/security-agent/intelligence/priorities?${queryParams.toString()}`),
        fetch(`${API_BASE}/api/security-agent/intelligence/history?${queryParams.toString()}`),
      ]);

      if (resOverview.ok) {
        const dataOverview = await resOverview.json();
        setIntelligenceOverview(dataOverview);
      }
      if (resPriorities.ok) {
        const dataPriorities = await resPriorities.json();
        setIntelligencePriorities(dataPriorities);
      }
      if (resHistory.ok) {
        const dataHistory = await resHistory.json();
        setIntelligenceHistory(dataHistory);
      }
    } catch (err) {
      setErrorMessage(err.message || "Failed to load dynamic intelligence");
    } finally {
      setIntelligenceLoading(false);
    }
  };

  useEffect(() => {
    if (activeTab === "intelligence" && !intelligenceOverview) {
      handleFetchIntelligence();
    }
  }, [activeTab]);

  // Phase E2: Attack Graph Handlers
  const handleFetchAttackGraph = async () => {
    setIsAnalyzingGraph(true);
    setErrorMessage("");
    try {
      const queryParams = new URLSearchParams({
        target_url: targetUrl || "http://127.0.0.1:8000",
        application_id: graphAppId || "default",
        app_version: graphVersion || "v1.0",
        environment: graphEnv || "sandbox",
      });
      const res = await fetch(`${API_BASE}/api/security-agent/attack-graph/full?${queryParams.toString()}`);
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || "Failed to analyze attack graph");
      }
      const data = await res.json();
      setAttackGraphData(data);
      if (data.sccs && data.sccs.length > 0 && !selectedSccId) {
        const firstCyclic = data.sccs.find((s) => s.is_cyclic) || data.sccs[0];
        setSelectedSccId(firstCyclic.component_id);
      }
    } catch (err) {
      setErrorMessage(err.message || "Failed to load attack graph");
    } finally {
      setIsAnalyzingGraph(false);
    }
  };

  const handleGenerateCandidatePaths = async () => {
    setIsGeneratingPaths(true);
    setErrorMessage("");
    try {
      const payload = {
        target_url: targetUrl || "http://127.0.0.1:8000",
        application_id: graphAppId || "default",
        app_version: graphVersion || "v1.0",
        environment: graphEnv || "sandbox",
        endpoint: graphEndpoint || "/api/chat",
        max_paths: 20,
        max_length: 5,
        user_confirmed_authorization: true,
      };
      const res = await fetch(`${API_BASE}/api/security-agent/attack-graph/candidate-paths`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || "Failed to generate candidate attack paths");
      }
      const data = await res.json();
      setCandidatePathsData(data);
      if (data.paths && data.paths.length > 0) {
        setSelectedPathId(data.paths[0].path_id);
      }
    } catch (err) {
      setErrorMessage(err.message || "Failed to generate candidate paths");
    } finally {
      setIsGeneratingPaths(false);
    }
  };

  useEffect(() => {
    if (activeTab === "attack_graph" && !attackGraphData) {
      handleFetchAttackGraph();
    }
  }, [activeTab]);

  // Phase E3: Deep OpenAPI Schema Intelligence Handlers
  const handleFetchLiveSchema = async () => {
    setIsAnalyzingSchema(true);
    setErrorMessage("");
    try {
      const queryParams = new URLSearchParams({
        target_url: targetUrl || "http://127.0.0.1:8000",
        user_confirmed_authorization: "true",
      });
      const res = await fetch(`${API_BASE}/api/security-agent/schema/live-analysis?${queryParams.toString()}`);
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || "Failed to analyze live OpenAPI schema");
      }
      const data = await res.json();
      setSchemaAnalysisData(data);
      if (data.endpoints && data.endpoints.length > 0) {
        setSelectedSchemaEndpoint(data.endpoints[0].endpoint);
      }
    } catch (err) {
      setErrorMessage(err.message || "Failed to perform live schema analysis");
    } finally {
      setIsAnalyzingSchema(false);
    }
  };

  const handleAnalyzeCustomSchema = async () => {
    if (!customSpecText.trim()) return;
    setIsAnalyzingSchema(true);
    setErrorMessage("");
    try {
      let parsed;
      try {
        parsed = JSON.parse(customSpecText);
      } catch (e) {
        throw new Error("Invalid JSON specification format: " + e.message);
      }
      const res = await fetch(`${API_BASE}/api/security-agent/schema/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          spec: parsed,
          target_url: targetUrl || "http://127.0.0.1:8000",
          user_confirmed_authorization: true,
        }),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || "Failed to analyze custom schema");
      }
      const data = await res.json();
      setSchemaAnalysisData(data);
      setCustomSpecModal(false);
      if (data.endpoints && data.endpoints.length > 0) {
        setSelectedSchemaEndpoint(data.endpoints[0].endpoint);
      }
    } catch (err) {
      setErrorMessage(err.message || "Custom schema analysis failed");
    } finally {
      setIsAnalyzingSchema(false);
    }
  };

  const handleGenerateSchemaTestPlans = async () => {
    setIsGeneratingSchemaTests(true);
    setErrorMessage("");
    try {
      const payload = {
        target_url: targetUrl || "http://127.0.0.1:8000",
        application_id: intelAppId || "default",
        app_version: intelVersion || "v1.0",
        environment: intelEnv || "sandbox",
        user_confirmed_authorization: true,
      };
      const res = await fetch(`${API_BASE}/api/security-agent/schema/test-plans`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || "Failed to generate schema test plans");
      }
      const data = await res.json();
      setSchemaTestPlansData(data);
      if (data.plans && data.plans.length > 0) {
        setSelectedTestPlanId(data.plans[0].test_id);
      }
    } catch (err) {
      setErrorMessage(err.message || "Failed to generate schema test plans");
    } finally {
      setIsGeneratingSchemaTests(false);
    }
  };

  useEffect(() => {
    if (activeTab === "schema_intelligence" && !schemaAnalysisData) {
      handleFetchLiveSchema();
    }
  }, [activeTab]);

  // Phase E4: Vulnerability & Evidence Lifecycle Handlers
  const handleFetchLifecycleBoard = async () => {
    setIsFetchingLifecycle(true);
    setErrorMessage("");
    try {
      const res = await fetch(`${API_BASE}/api/security-agent/lifecycle/board?target_identity=${encodeURIComponent(targetUrl || "http://127.0.0.1:8000")}`);
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || "Failed to load lifecycle board");
      }
      const data = await res.json();
      setLifecycleBoard(data);
    } catch (err) {
      setErrorMessage(err.message || "Failed to fetch lifecycle board");
    } finally {
      setIsFetchingLifecycle(false);
    }
  };

  const handleSelectLifecycleFinding = async (findingId) => {
    try {
      const res = await fetch(`${API_BASE}/api/security-agent/findings/${findingId}`);
      if (!res.ok) throw new Error("Failed to load finding details");
      const data = await res.json();
      setSelectedLifecycleFinding(data);
      setLifecycleTransitionTarget("");
      setLifecycleTransitionReason("");
      setLifecycleTransitionEvidence("");
      setLifecycleIsSecondaryConfirmed(false);
    } catch (err) {
      setErrorMessage(err.message || "Error loading finding details");
    }
  };

  const handleExecuteLifecycleTransition = async () => {
    if (!selectedLifecycleFinding || !lifecycleTransitionTarget) return;
    if (!lifecycleTransitionReason.trim() || lifecycleTransitionReason.trim().length < 3) {
      setErrorMessage("A valid justification reason (at least 3 characters) is required for state transitions.");
      return;
    }
    setIsExecutingTransition(true);
    setErrorMessage("");
    try {
      const payload = {
        target_state: lifecycleTransitionTarget,
        transition_reason: lifecycleTransitionReason.trim(),
        actor: "LeadSecurityAuditor",
        evidence_reference: lifecycleTransitionEvidence.trim() || undefined,
        is_secondary_confirmed: lifecycleIsSecondaryConfirmed,
      };
      const res = await fetch(`${API_BASE}/api/security-agent/findings/${selectedLifecycleFinding.finding_id}/transition`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || "Failed to execute state transition");
      }
      const updated = await res.json();
      setSelectedLifecycleFinding(updated);
      setStatusMessage(`Successfully transitioned finding ${updated.finding_id} to ${updated.lifecycle_status}`);
      handleFetchLifecycleBoard();
    } catch (err) {
      setErrorMessage(err.message || "State transition failed");
    } finally {
      setIsExecutingTransition(false);
    }
  };

  const handleRegisterFindingFromRca = async () => {
    if (!rcaFinding) {
      setErrorMessage("No active RCA finding available to register.");
      return;
    }
    setErrorMessage("");
    try {
      const payload = {
        scenario_id: rcaFinding.scenario_id,
        risk_id: rcaFinding.associated_risk,
        title: `${rcaFinding.associated_risk} - ${rcaFinding.root_cause_category}: ${rcaFinding.affected_endpoint}`,
        description: rcaFinding.explanation,
        category: "OWASP_LLM",
        affected_endpoint: rcaFinding.affected_endpoint,
        http_method: "POST",
        target_identity: targetUrl || "http://127.0.0.1:8000",
        initial_status: rcaFinding.status === "CONFIRMED" ? "POTENTIAL" : "DETECTED",
        severity: rcaFinding.severity,
        confidence: rcaFinding.confidence,
        cvss_score: rcaFinding.cvss_score,
        cvss_vector: rcaFinding.cvss_vector,
        root_cause_category: rcaFinding.root_cause_category,
        failed_security_control: rcaFinding.failed_security_control,
        trust_boundary_crossed: rcaFinding.trust_boundary_crossed,
        evidence_references: rcaFinding.evidence_references || [],
        initial_reason: "Registered from Root Cause Analysis Engine assessment",
        actor: "AutonomousSecurityAgent",
      };
      const res = await fetch(`${API_BASE}/api/security-agent/findings`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || "Failed to register finding");
      }
      const created = await res.json();
      setStatusMessage(`Finding ${created.finding_id} registered into lifecycle database!`);
      setActiveTab("lifecycle");
      handleSelectLifecycleFinding(created.finding_id);
      handleFetchLifecycleBoard();
    } catch (err) {
      setErrorMessage(err.message || "Failed to register finding from RCA");
    }
  };

  useEffect(() => {
    if (activeTab === "lifecycle" && !lifecycleBoard) {
      handleFetchLifecycleBoard();
    }
  }, [activeTab]);

  // Phase E5 Regression Intelligence Handlers
  const handleRunRegressionComparison = async (overrideBaseId, overrideCurrId) => {
    const baseId = overrideBaseId || regressionBaselinePlanId;
    const currId = overrideCurrId || regressionCurrentPlanId;
    if (!baseId || !currId) {
      setErrorMessage("Both Baseline Plan ID and Current Plan ID are required for regression comparison.");
      return;
    }
    setIsComparingRegression(true);
    setErrorMessage("");
    try {
      const res = await fetch(`${API_BASE}/api/security-agent/regression/compare`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          baseline_plan_id: baseId,
          current_plan_id: currId,
          allow_cross_target: regressionAllowCrossTarget,
          allow_cross_environment: regressionAllowCrossEnv,
        }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || "Regression comparison failed");
      }
      const data = await res.json();
      setRegressionComparison(data);
      setStatusMessage(`Regression comparison complete: ${data.regression_verdict}`);
      handleFetchRegressionHistory();
    } catch (err) {
      setErrorMessage(err.message || "Failed to execute regression comparison");
    } finally {
      setIsComparingRegression(false);
    }
  };

  const handleFetchRegressionHistory = async () => {
    setIsFetchingRegressionHistory(true);
    try {
      const res = await fetch(`${API_BASE}/api/security-agent/regression/history?limit=20`);
      if (res.ok) {
        const data = await res.json();
        setRegressionHistory(data.comparisons || []);
      }
    } catch (err) {
      console.error("Failed to fetch regression history:", err);
    } finally {
      setIsFetchingRegressionHistory(false);
    }
  };

  const handleSelectRegressionComparison = async (comparisonId) => {
    setIsComparingRegression(true);
    try {
      const res = await fetch(`${API_BASE}/api/security-agent/regression/${comparisonId}`);
      if (res.ok) {
        const data = await res.json();
        setRegressionComparison(data);
        setRegressionBaselinePlanId(data.baseline_plan_id || "");
        setRegressionCurrentPlanId(data.current_plan_id || "");
      }
    } catch (err) {
      setErrorMessage("Failed to load historical comparison");
    } finally {
      setIsComparingRegression(false);
    }
  };

  useEffect(() => {
    if (activeTab === "regression" && regressionHistory.length === 0) {
      handleFetchRegressionHistory();
    }
  }, [activeTab]);

  const handleFetchEnterpriseReports = async () => {
    setIsFetchingEnterpriseReports(true);
    try {
      const res = await fetch(`${API_BASE}/api/security-agent/reports/history`);
      if (res.ok) {
        const data = await res.json();
        setEnterpriseReportsList(data.reports || []);
      }
    } catch (err) {
      console.error("Failed to fetch enterprise reports history:", err);
    } finally {
      setIsFetchingEnterpriseReports(false);
    }
  };

  const handleLoadEnterpriseReportDetail = async (reportId) => {
    try {
      const res = await fetch(`${API_BASE}/api/security-agent/reports/${reportId}`);
      if (res.ok) {
        const data = await res.json();
        setSelectedEnterpriseReport(data);
        setReportVerificationResult(null);
      }
    } catch (err) {
      console.error("Failed to load report detail:", err);
    }
  };

  const handleGenerateEnterpriseReport = async () => {
    setIsGeneratingEnterpriseReport(true);
    setReportVerificationResult(null);
    try {
      const formats = [];
      if (reportFormatJson) formats.push("json");
      if (reportFormatPdf) formats.push("pdf");
      if (reportFormatXlsx) formats.push("xlsx");
      if (reportFormatCsv) formats.push("csv");

      const payload = {
        session_id: reportSessionIdInput.trim() || undefined,
        plan_id: reportPlanIdInput.trim() || undefined,
        report_type: reportTypeSelection,
        lead_auditor: reportLeadAuditor,
        formats: formats.length > 0 ? formats : ["json", "pdf", "xlsx", "csv"],
      };

      const res = await fetch(`${API_BASE}/api/security-agent/reports/generate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (res.ok) {
        const data = await res.json();
        setSelectedEnterpriseReport(data);
        handleFetchEnterpriseReports();
      } else {
        const err = await res.json();
        alert(`Report generation failed: ${err.detail || "Unknown error"}`);
      }
    } catch (err) {
      console.error("Report generation failed:", err);
      alert(`Report generation failed: ${err.message}`);
    } finally {
      setIsGeneratingEnterpriseReport(false);
    }
  };

  const handleVerifyEnterpriseReport = async (reportId) => {
    setIsVerifyingEnterpriseReport(true);
    try {
      const res = await fetch(`${API_BASE}/api/security-agent/reports/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ report_id: reportId }),
      });
      if (res.ok) {
        const data = await res.json();
        setReportVerificationResult(data);
      }
    } catch (err) {
      console.error("Report verification failed:", err);
    } finally {
      setIsVerifyingEnterpriseReport(false);
    }
  };

  // Phase E7: Explainability Handlers
  const handleFetchDecisions = async (filterOverride) => {
    setIsFetchingDecisions(true);
    try {
      const type = filterOverride !== undefined ? filterOverride : decisionFilterType;
      const q = new URLSearchParams({ limit: "100" });
      if (type) q.append("decision_type", type);
      if (sharedSessionFilter) q.append("session_id", sharedSessionFilter);
      if (sharedFindingFilter) q.append("finding_id", sharedFindingFilter);
      const url = `/api/security-agent/decisions?${q.toString()}`;
      const res = await fetch(url);
      if (res.ok) {
        const data = await res.json();
        const items = data.decisions || [];
        setDecisionsList(items);
        if (items.length > 0 && !selectedDecision) {
          setSelectedDecision(items[0]);
        }
      }
    } catch (e) {
      console.error("Failed to fetch decisions", e);
    } finally {
      setIsFetchingDecisions(false);
    }
  };

  useEffect(() => {
    if (activeTab === "explainability") {
      handleFetchDecisions();
    }
  }, [activeTab, sharedSessionFilter, sharedFindingFilter]);

  // Phase E8: Operations Monitoring & Telemetry Handlers
  const handleFetchOperationsAll = async () => {
    setIsFetchingOperations(true);
    setOpsActionFeedback(null);
    try {
      const [resOverview, resHealth, resHmac, resCb] = await Promise.all([
        fetch("/api/security-agent/operations/overview"),
        fetch("/api/security-agent/operations/health"),
        fetch("/api/security-agent/operations/hmac-audit"),
        fetch("/api/security-agent/operations/circuit-breaker"),
      ]);
      if (resOverview.ok) setOperationsOverview(await resOverview.json());
      if (resHealth.ok) setOperationsHealth(await resHealth.json());
      if (resHmac.ok) setHmacAuditData(await resHmac.json());
      if (resCb.ok) {
        const cbData = await resCb.json();
        setCircuitBreakers(cbData.circuits || []);
      }
    } catch (e) {
      console.error("Failed to fetch operational telemetry", e);
      setOpsActionFeedback({ type: "error", message: "Failed to communicate with operations monitor." });
    } finally {
      setIsFetchingOperations(false);
    }
  };

  const handleResetCircuitBreakers = async (targetSession) => {
    setOpsActionFeedback(null);
    try {
      const body = {
        session_id: targetSession || null,
        admin_token: opsAdminToken || "apexshield_ops_admin_2026",
      };
      const res = await fetch("/api/security-agent/operations/circuit-breaker/reset", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (res.ok) {
        const data = await res.json();
        setOpsActionFeedback({ type: "success", message: data.message || "Circuit breaker reset successful." });
        handleFetchOperationsAll();
      } else {
        const err = await res.json();
        setOpsActionFeedback({ type: "error", message: err.detail || "Administrative reset unauthorized." });
      }
    } catch (e) {
      setOpsActionFeedback({ type: "error", message: "Network error during circuit reset." });
    }
  };

  useEffect(() => {
    if (activeTab === "operations") {
      handleFetchOperationsAll();
    }
  }, [activeTab]);

  // Phase E9: Enterprise Security Operations Center (SOC) Handlers & Context
  const handleFetchSocOverview = async () => {
    setIsFetchingSocOverview(true);
    try {
      const q = new URLSearchParams();
      if (sharedSessionFilter) q.append("session_id", sharedSessionFilter);
      if (targetUrl) q.append("target_url", targetUrl);
      const res = await fetch(`/api/security-agent/soc/overview?${q.toString()}`);
      if (res.ok) {
        const data = await res.json();
        setSocOverviewData(data);
      }
    } catch (e) {
      console.error("Failed to fetch SOC overview", e);
    } finally {
      setIsFetchingSocOverview(false);
    }
  };

  const navigateToSocView = (viewKey, context = {}) => {
    if (context.findingId) {
      setSharedFindingFilter(context.findingId);
      setSelectedLifecycleFinding(context.findingId);
      if (viewKey === "explainability") {
        handleFetchDecisions();
      }
    }
    if (context.sessionId) {
      setSharedSessionFilter(context.sessionId);
      setReportSessionIdInput(context.sessionId);
    }
    if (context.planId) {
      setSharedPlanFilter(context.planId);
      setReportPlanIdInput(context.planId);
      setRegressionCurrentPlanId(context.planId);
    }
    setActiveTab(viewKey);
    setTimeout(() => {
      const el = document.getElementById("main-tabs-container") || document.getElementById("claude-code-assessment-view");
      if (el) {
        el.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    }, 50);
  };

  useEffect(() => {
    if (activeTab === "soc_overview") {
      handleFetchSocOverview();
    }
  }, [activeTab, sharedSessionFilter, targetUrl]);

  // Claude Code Handlers
  const handleLoadClaudeSample = async () => {
    setIsLoadingClaudeSample(true);
    setClaudeCodeError(null);
    try {
      const res = await fetch(`${API_BASE}/api/security-agent/claude-code/sample`);
      if (!res.ok) throw new Error(`Failed to load sample: ${res.status}`);
      const data = await res.json();
      setClaudeCodeFiles({
        claude_md: data.claude_md || "",
        settings_json: data.settings_json || "",
        settings_local_json: data.settings_local_json || "",
        report_writer_md: data.report_writer_md || "",
      });
    } catch (err) {
      setClaudeCodeError(`Sample load error: ${err.message}`);
    } finally {
      setIsLoadingClaudeSample(false);
    }
  };

  const handleEvaluateClaudeCode = async () => {
    setIsEvaluatingClaudeCode(true);
    setClaudeCodeError(null);
    try {
      const res = await fetch(`${API_BASE}/api/security-agent/claude-code/evaluate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(claudeCodeFiles),
      });
      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.detail || `Evaluation failed with status ${res.status}`);
      }
      const data = await res.json();
      setClaudeCodeResult(data);
    } catch (err) {
      setClaudeCodeError(`Assessment error: ${err.message}`);
    } finally {
      setIsEvaluatingClaudeCode(false);
    }
  };

  const handleExportClaudeCode = async (format) => {
    if (!claudeCodeResult) return;
    setClaudeCodeExporting(format);
    try {
      const res = await fetch(`${API_BASE}/api/security-agent/claude-code/export/${format}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(claudeCodeResult),
      });
      if (!res.ok) throw new Error(`Export failed with status ${res.status}`);
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `ApexShield_Claude_Code_Assessment_${(claudeCodeResult.evaluation_id || "eval").slice(0, 8)}.${format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err) {
      setClaudeCodeError(`Export error: ${err.message}`);
    } finally {
      setClaudeCodeExporting(null);
    }
  };

  useEffect(() => {
    if (activeTab === "claude_code" && !claudeCodeFiles.claude_md && !isLoadingClaudeSample) {
      handleLoadClaudeSample();
    }
  }, [activeTab]);

  return (
    <div className="security-agent-container" style={{ padding: "20px 24px", height: "100%", overflowY: "auto", background: "var(--bg-primary)" }}>
      {/* Top Banner / Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "20px" }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "6px" }}>
            <span style={{ fontSize: "20px" }}>🛡️</span>
            <h1 style={{ fontSize: "20px", fontWeight: "800", letterSpacing: "0.5px", color: "var(--text-main)" }}>
              Autonomous AI Security Testing Agent
            </h1>
            <span style={{ fontSize: "11px", padding: "2px 8px", borderRadius: "12px", background: "rgba(99,102,241,0.2)", color: "var(--accent-primary)", border: "1px solid rgba(99,102,241,0.4)", fontWeight: "600" }}>
              PHASE D · ADVANCED VULNERABILITY INTELLIGENCE & ATTACK ORCHESTRATION
            </span>
          </div>
          <p style={{ fontSize: "13px", color: "var(--text-muted)" }}>
            Autonomous reconnaissance, 20-risk OWASP correlation, multi-stage attack chains, CVSS v3.1 Root Cause Engine & automated remediation intelligence.
          </p>
        </div>

        {/* Backend Status Badge */}
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <div style={{ textAlign: "right", fontSize: "11px" }}>
            <div style={{ color: "var(--text-dim)" }}>BACKEND STATUS</div>
            <div style={{ color: backendHealth?.online ? "var(--color-online)" : "var(--color-error)", fontWeight: "700" }}>
              {backendHealth?.online ? "CONNECTED (PORT 8000)" : "DISCONNECTED"}
            </div>
          </div>
          <span style={{ width: "10px", height: "10px", borderRadius: "50%", background: backendHealth?.online ? "var(--color-online)" : "var(--color-error)", display: "inline-block" }} />
        </div>
      </div>

      {/* Quick Starters & Directives */}
      <div style={{ marginBottom: "16px" }}>
        <div style={{ fontSize: "11px", fontWeight: "600", color: "var(--text-muted)", marginBottom: "8px", textTransform: "uppercase", letterSpacing: "0.5px" }}>
          ⚡ Quick Autonomous Directives
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "8px" }}>
          {QUICK_SECURITY_COMMANDS.map((item, idx) => (
            <button
              key={idx}
              id={item.tabTarget === "claude_code" ? "claude-code-audit-card" : undefined}
              data-testid={item.tabTarget === "claude_code" ? "claude-code-audit-card" : undefined}
              type="button"
              onClick={() => {
                setCommand(item.command);
                setChainCommand(item.command);
                if (item.tabTarget) {
                  navigateToSocView(item.tabTarget);
                  if (!claudeCodeFiles.claude_md && !isLoadingClaudeSample) {
                    handleLoadClaudeSample();
                  }
                }
              }}
              disabled={item.tabTarget ? false : isExecuting}
              style={{
                textAlign: "left",
                padding: "8px 12px",
                borderRadius: "8px",
                background: activeTab === item.tabTarget ? "rgba(168, 85, 247, 0.18)" : "var(--bg-surface)",
                border: activeTab === item.tabTarget ? "1px solid #c084fc" : "1px solid var(--border-subtle)",
                cursor: "pointer",
                transition: "all 0.15s ease",
                position: "relative",
                zIndex: 2,
                pointerEvents: "auto",
              }}
            >
              <div style={{ fontSize: "12px", fontWeight: "700", color: item.tabTarget === "claude_code" ? "#c084fc" : "var(--accent-cyan)", marginBottom: "2px", pointerEvents: "none" }}>
                {item.label}
              </div>
              <div style={{ fontSize: "11px", color: "var(--text-muted)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", pointerEvents: "none" }}>
                {item.command}
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Control Panel: Natural Language Command & Configuration */}
      <div style={{ background: "var(--bg-surface)", border: "1px solid var(--border-subtle)", borderRadius: "12px", padding: "16px", marginBottom: "20px" }}>
        <div style={{ display: "flex", gap: "12px", marginBottom: "12px" }}>
          {/* Natural Language Command Bar */}
          <div style={{ flex: 1 }}>
            <label style={{ display: "block", fontSize: "11px", fontWeight: "700", color: "var(--text-muted)", marginBottom: "4px" }}>
              NATURAL LANGUAGE SECURITY COMMAND
            </label>
            <input
              type="text"
              value={command}
              onChange={(e) => setCommand(e.target.value)}
              disabled={isExecuting}
              placeholder="e.g. Audit my agent for LLM01, ASI01, and ASI02 against http://127.0.0.1:8000"
              style={{
                width: "100%",
                padding: "10px 14px",
                borderRadius: "8px",
                background: "var(--bg-primary)",
                border: "1px solid var(--border-subtle)",
                color: "var(--text-main)",
                fontSize: "13px",
                fontFamily: "inherit",
              }}
            />
          </div>

          {/* Action Button */}
          <div style={{ display: "flex", alignItems: "flex-end", gap: "8px" }}>
            <button
              onClick={handleExecuteAdaptivePlan}
              disabled={isExecuting || !userAuthorized}
              style={{
                padding: "10px 18px",
                borderRadius: "8px",
                background: isExecuting ? "var(--bg-surface-elevated)" : "var(--accent-primary)",
                color: "#ffffff",
                border: "none",
                fontSize: "13px",
                fontWeight: "700",
                cursor: isExecuting || !userAuthorized ? "not-allowed" : "pointer",
                display: "flex",
                alignItems: "center",
                gap: "8px",
                boxShadow: isExecuting ? "none" : "0 2px 8px rgba(99,102,241,0.3)",
              }}
            >
              {isExecuting ? (
                <>
                  <span style={{ display: "inline-block", animation: "spin 1s linear infinite" }}>🔄</span>
                  <span>Executing Plan...</span>
                </>
              ) : (
                <>
                  <span>🚀</span>
                  <span>Execute Adaptive Plan</span>
                </>
              )}
            </button>

            {isExecuting && (
              <button
                onClick={handleCancelExecution}
                style={{
                  padding: "10px 14px",
                  borderRadius: "8px",
                  background: "rgba(239, 68, 68, 0.2)",
                  color: "var(--color-error)",
                  border: "1px solid rgba(239, 68, 68, 0.4)",
                  fontSize: "13px",
                  fontWeight: "600",
                  cursor: "pointer",
                }}
              >
                Cancel
              </button>
            )}
          </div>
        </div>

        {/* Live Autonomous Command Interpretation Preview */}
        {(isInterpreting || interpretationPreview) && (
          <div
            style={{
              marginBottom: "14px",
              padding: "10px 14px",
              borderRadius: "8px",
              background: interpretationPreview?.blocking_reasons?.length > 0
                ? "rgba(239, 68, 68, 0.12)"
                : interpretationPreview?.identified_risks?.length > 0
                ? "rgba(99, 102, 241, 0.12)"
                : "rgba(30, 41, 59, 0.6)",
              border: `1px solid ${
                interpretationPreview?.blocking_reasons?.length > 0
                  ? "rgba(239, 68, 68, 0.4)"
                  : interpretationPreview?.identified_risks?.length > 0
                  ? "rgba(99, 102, 241, 0.35)"
                  : "var(--border-subtle)"
              }`,
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: "12px",
              fontSize: "12px",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "8px", flex: 1 }}>
              {isInterpreting ? (
                <>
                  <span style={{ display: "inline-block", animation: "spin 1s linear infinite" }}>🔄</span>
                  <span style={{ color: "var(--text-muted)" }}>
                    Interpreting security command with AI reasoning engine...
                  </span>
                </>
              ) : interpretationPreview?.blocking_reasons?.length > 0 ? (
                <>
                  <span style={{ fontSize: "16px" }}>⚠️</span>
                  <div>
                    <div style={{ fontWeight: "700", color: "var(--color-error)" }}>
                      Command Execution Blocked: Unsupported Risk Identifier
                    </div>
                    <div style={{ fontSize: "11px", color: "#fca5a5", marginTop: "2px" }}>
                      {interpretationPreview.blocking_reasons.join(" | ")}
                    </div>
                  </div>
                </>
              ) : interpretationPreview?.identified_risks?.length > 0 ? (
                <>
                  <span style={{ fontSize: "16px" }}>🎯</span>
                  <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: "8px" }}>
                    <span style={{ fontWeight: "700", color: "var(--accent-cyan)" }}>
                      Autonomous Intent Recognized:
                    </span>
                    <span style={{ color: "var(--text-main)" }}>
                      Identified {interpretationPreview.identified_risks.length} Target Risk(s)
                    </span>
                    <div style={{ display: "inline-flex", gap: "4px" }}>
                      {interpretationPreview.identified_risks.map((r) => (
                        <span
                          key={r.risk_id}
                          style={{
                            padding: "1px 6px",
                            borderRadius: "4px",
                            background: "rgba(99, 102, 241, 0.3)",
                            border: "1px solid rgba(99, 102, 241, 0.5)",
                            color: "#c7d2fe",
                            fontSize: "11px",
                            fontWeight: "700",
                          }}
                        >
                          {r.risk_id}
                        </span>
                      ))}
                    </div>
                    <span style={{ color: "var(--text-dim)", fontSize: "11px" }}>
                      → Planned {interpretationPreview.plan_preview?.total_scenarios || (interpretationPreview.identified_risks.length * 3)} attack scenarios
                    </span>
                  </div>
                </>
              ) : (
                <>
                  <span style={{ fontSize: "14px" }}>💡</span>
                  <span style={{ color: "var(--text-dim)" }}>
                    Natural-language command parsed. Ready for execution against target.
                  </span>
                </>
              )}
            </div>
            {interpretationPreview && (
              <span
                style={{
                  fontSize: "10px",
                  fontWeight: "700",
                  padding: "2px 8px",
                  borderRadius: "10px",
                  background: interpretationPreview?.blocking_reasons?.length > 0 ? "rgba(239, 68, 68, 0.25)" : "rgba(34, 197, 94, 0.2)",
                  color: interpretationPreview?.blocking_reasons?.length > 0 ? "var(--color-error)" : "#4ade80",
                  textTransform: "uppercase",
                  letterSpacing: "0.5px",
                }}
              >
                {interpretationPreview?.blocking_reasons?.length > 0 ? "Validation Failed" : "Validated Plan"}
              </span>
            )}
          </div>
        )}

        {/* Target & Execution Parameters Row */}
        <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr 1.5fr", gap: "12px", alignItems: "center" }}>
          {/* Target URL */}
          <div>
            <label style={{ display: "block", fontSize: "11px", fontWeight: "700", color: "var(--text-muted)", marginBottom: "4px" }}>
              TARGET BASE URL
            </label>
            <input
              type="text"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              disabled={isExecuting}
              style={{
                width: "100%",
                padding: "7px 10px",
                borderRadius: "6px",
                background: "var(--bg-primary)",
                border: `1px solid ${targetValidation?.is_in_scope ? "rgba(34,197,94,0.4)" : "var(--border-subtle)"}`,
                color: "var(--text-main)",
                fontSize: "12px",
                fontFamily: "DM Mono, monospace",
              }}
            />
          </div>

          {/* Testing Stage */}
          <div>
            <label style={{ display: "block", fontSize: "11px", fontWeight: "700", color: "var(--text-muted)", marginBottom: "4px" }}>
              STAGE
            </label>
            <select
              value={stage}
              onChange={(e) => setStage(e.target.value)}
              disabled={isExecuting}
              style={{
                width: "100%",
                padding: "7px 10px",
                borderRadius: "6px",
                background: "var(--bg-primary)",
                border: "1px solid var(--border-subtle)",
                color: "var(--text-main)",
                fontSize: "12px",
              }}
            >
              <option value="POST_MITIGATION">POST_MITIGATION (Hardened)</option>
              <option value="BASELINE">BASELINE (Vulnerable)</option>
            </select>
          </div>

          {/* Max Multi-Turn Probes */}
          <div>
            <label style={{ display: "block", fontSize: "11px", fontWeight: "700", color: "var(--text-muted)", marginBottom: "4px" }}>
              MAX TURNS / CHAIN
            </label>
            <select
              value={maxTurns}
              onChange={(e) => setMaxTurns(Number(e.target.value))}
              disabled={isExecuting}
              style={{
                width: "100%",
                padding: "7px 10px",
                borderRadius: "6px",
                background: "var(--bg-primary)",
                border: "1px solid var(--border-subtle)",
                color: "var(--text-main)",
                fontSize: "12px",
              }}
            >
              <option value={1}>1 Turn (Single Probe)</option>
              <option value={2}>2 Turns (Confirmed Probe)</option>
              <option value={3}>3 Turns (Full Adaptive Loop)</option>
            </select>
          </div>

          {/* Target Scope & Authorization Checkbox */}
          <div>
            <label style={{ display: "block", fontSize: "11px", fontWeight: "700", color: "var(--text-muted)", marginBottom: "4px" }}>
              SCOPE AUTHORIZATION
            </label>
            <label style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "12px", color: "var(--text-main)", cursor: "pointer" }}>
              <input
                type="checkbox"
                checked={userAuthorized}
                onChange={(e) => setUserAuthorized(e.target.checked)}
                disabled={isExecuting}
              />
              <span>I confirm explicit authorization for this target</span>
            </label>
          </div>
        </div>

        {/* Status / Feedback message */}
        {(statusMessage || errorMessage) && (
          <div
            style={{
              marginTop: "12px",
              padding: "8px 12px",
              borderRadius: "6px",
              background: errorMessage ? "rgba(239,68,68,0.15)" : "rgba(99,102,241,0.12)",
              border: `1px solid ${errorMessage ? "rgba(239,68,68,0.3)" : "rgba(99,102,241,0.25)"}`,
              fontSize: "12px",
              color: errorMessage ? "var(--color-error)" : "var(--accent-cyan)",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <span>{errorMessage || statusMessage}</span>
            {errorMessage && (
              <button
                onClick={() => setErrorMessage("")}
                style={{ background: "transparent", border: "none", color: "var(--text-dim)", cursor: "pointer", fontSize: "12px" }}
              >
                ✕
              </button>
            )}
          </div>
        )}

        {/* Risk Selection Pills */}
        <div style={{ marginTop: "12px" }}>
          <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--text-muted)", marginBottom: "6px" }}>
            SELECT TARGET OWASP RISKS
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
            {risksList.map((r) => {
              const isSelected = selectedRisks.includes(r.risk_id);
              return (
                <button
                  key={r.risk_id}
                  onClick={() => toggleRisk(r.risk_id)}
                  disabled={isExecuting}
                  style={{
                    padding: "3px 8px",
                    borderRadius: "6px",
                    background: isSelected ? "rgba(99,102,241,0.25)" : "var(--bg-surface-elevated)",
                    border: `1px solid ${isSelected ? "var(--accent-primary)" : "var(--border-subtle)"}`,
                    color: isSelected ? "var(--text-main)" : "var(--text-dim)",
                    fontSize: "11px",
                    cursor: "pointer",
                    display: "flex",
                    alignItems: "center",
                    gap: "4px",
                  }}
                >
                  <span style={{ fontWeight: "700" }}>{r.risk_id}</span>
                  <span style={{ fontSize: "10px", color: isSelected ? "var(--text-muted)" : "var(--text-dim)" }}>
                    {r.risk_name}
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Consolidated Autonomous Assessment Card (Single Unified Screen) */}
      {activePlan && (
        <div
          style={{
            background: "linear-gradient(135deg, rgba(17, 24, 39, 0.95), rgba(15, 23, 42, 0.98))",
            border: "1px solid rgba(99, 102, 241, 0.4)",
            borderRadius: "14px",
            padding: "20px",
            marginBottom: "20px",
            boxShadow: "0 8px 32px rgba(0, 0, 0, 0.35)",
          }}
        >
          {/* Card Header & High-Level Verdict */}
          <div style={{ display: "flex", flexWrap: "wrap", justifyContent: "space-between", alignItems: "flex-start", gap: "12px", borderBottom: "1px solid rgba(255, 255, 255, 0.08)", paddingBottom: "16px", marginBottom: "16px" }}>
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "4px" }}>
                <span style={{ fontSize: "24px" }}>🛡️</span>
                <span style={{ fontSize: "18px", fontWeight: "800", color: "#f8fafc", letterSpacing: "0.5px" }}>
                  Autonomous OWASP Security Assessment Result
                </span>
                <span
                  style={{
                    padding: "3px 10px",
                    borderRadius: "12px",
                    fontSize: "11px",
                    fontWeight: "700",
                    background: activePlan.stage === "POST_MITIGATION" ? "rgba(34, 197, 94, 0.2)" : "rgba(234, 179, 8, 0.2)",
                    color: activePlan.stage === "POST_MITIGATION" ? "#4ade80" : "#facc15",
                    border: `1px solid ${activePlan.stage === "POST_MITIGATION" ? "rgba(34, 197, 94, 0.4)" : "rgba(234, 179, 8, 0.4)"}`,
                  }}
                >
                  {activePlan.stage === "POST_MITIGATION" ? "POST_MITIGATION (Hardened)" : "BASELINE (Vulnerable)"}
                </span>
              </div>
              <div style={{ fontSize: "12px", color: "var(--text-muted)", display: "flex", gap: "16px", flexWrap: "wrap" }}>
                <span>Plan ID: <strong style={{ color: "var(--text-main)", fontFamily: "DM Mono, monospace" }}>{activePlan.plan_id.slice(0, 8)}...</strong></span>
                <span>Session ID: <strong style={{ color: "var(--text-main)", fontFamily: "DM Mono, monospace" }}>{activePlan.session_id.slice(0, 8)}...</strong></span>
                <span>Target: <strong style={{ color: "var(--accent-cyan)", fontFamily: "DM Mono, monospace" }}>{activePlan.target_url}</strong></span>
              </div>
            </div>

            {/* Overall Verdict Badge */}
            <div
              style={{
                padding: "8px 16px",
                borderRadius: "10px",
                background: (activePlan.vulnerabilities_confirmed || 0) === 0 ? "rgba(34, 197, 94, 0.15)" : "rgba(239, 68, 68, 0.18)",
                border: `1px solid ${(activePlan.vulnerabilities_confirmed || 0) === 0 ? "rgba(34, 197, 94, 0.5)" : "rgba(239, 68, 68, 0.5)"}`,
                textAlign: "right",
              }}
            >
              <div
                style={{
                  fontSize: "14px",
                  fontWeight: "800",
                  color: (activePlan.vulnerabilities_confirmed || 0) === 0 ? "#4ade80" : "#f87171",
                  display: "flex",
                  alignItems: "center",
                  gap: "6px",
                  justifyContent: "flex-end",
                }}
              >
                <span>{(activePlan.vulnerabilities_confirmed || 0) === 0 ? "✅" : "⚠️"}</span>
                <span>{(activePlan.vulnerabilities_confirmed || 0) === 0 ? "SECURED (ALL ATTACKS BLOCKED)" : "VULNERABILITIES CONFIRMED"}</span>
              </div>
              <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "2px" }}>
                Resilience Score: <strong style={{ color: "#ffffff" }}>{activePlan.resilience_score_percent}%</strong>
              </div>
            </div>
          </div>

          {/* 6-Card Metrics Grid */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))", gap: "10px", marginBottom: "16px" }}>
            <div style={{ background: "rgba(30, 41, 59, 0.5)", border: "1px solid var(--border-subtle)", borderRadius: "8px", padding: "10px 12px" }}>
              <div style={{ fontSize: "10px", fontWeight: "700", color: "var(--text-muted)", textTransform: "uppercase" }}>Target Risks</div>
              <div style={{ fontSize: "20px", fontWeight: "800", color: "var(--accent-cyan)", marginTop: "4px" }}>
                {activePlan.risk_assessments ? Object.keys(activePlan.risk_assessments).length : selectedRisks.length}
              </div>
              <div style={{ fontSize: "10px", color: "var(--text-dim)", marginTop: "2px" }}>OWASP Categories</div>
            </div>

            <div style={{ background: "rgba(30, 41, 59, 0.5)", border: "1px solid var(--border-subtle)", borderRadius: "8px", padding: "10px 12px" }}>
              <div style={{ fontSize: "10px", fontWeight: "700", color: "var(--text-muted)", textTransform: "uppercase" }}>Scenarios Tested</div>
              <div style={{ fontSize: "20px", fontWeight: "800", color: "#f8fafc", marginTop: "4px" }}>
                {activePlan.total_scenarios_executed} <span style={{ fontSize: "13px", color: "var(--text-muted)" }}>/ {activePlan.total_scenarios_planned}</span>
              </div>
              <div style={{ fontSize: "10px", color: "var(--text-dim)", marginTop: "2px" }}>Autonomous probes</div>
            </div>

            <div style={{ background: "rgba(30, 41, 59, 0.5)", border: "1px solid var(--border-subtle)", borderRadius: "8px", padding: "10px 12px" }}>
              <div style={{ fontSize: "10px", fontWeight: "700", color: "var(--text-muted)", textTransform: "uppercase" }}>Attacks Blocked</div>
              <div style={{ fontSize: "20px", fontWeight: "800", color: "#4ade80", marginTop: "4px" }}>
                {report?.blocked_scenarios ?? (activePlan.total_scenarios_executed - (activePlan.vulnerabilities_confirmed || 0))}
              </div>
              <div style={{ fontSize: "10px", color: "#86efac", marginTop: "2px" }}>Defenses held</div>
            </div>

            <div style={{ background: "rgba(30, 41, 59, 0.5)", border: "1px solid var(--border-subtle)", borderRadius: "8px", padding: "10px 12px" }}>
              <div style={{ fontSize: "10px", fontWeight: "700", color: "var(--text-muted)", textTransform: "uppercase" }}>Vulnerabilities</div>
              <div style={{ fontSize: "20px", fontWeight: "800", color: (activePlan.vulnerabilities_confirmed || 0) > 0 ? "#f87171" : "#4ade80", marginTop: "4px" }}>
                {activePlan.vulnerabilities_confirmed || 0}
              </div>
              <div style={{ fontSize: "10px", color: "var(--text-dim)", marginTop: "2px" }}>Confirmed breaches</div>
            </div>

            <div style={{ background: "rgba(30, 41, 59, 0.5)", border: "1px solid var(--border-subtle)", borderRadius: "8px", padding: "10px 12px" }}>
              <div style={{ fontSize: "10px", fontWeight: "700", color: "var(--text-muted)", textTransform: "uppercase" }}>Multi-Turn Probes</div>
              <div style={{ fontSize: "20px", fontWeight: "800", color: "#a5b4fc", marginTop: "4px" }}>
                {activePlan.total_turns_executed || 0}
              </div>
              <div style={{ fontSize: "10px", color: "var(--text-dim)", marginTop: "2px" }}>Wire dispatches</div>
            </div>

            <div style={{ background: "rgba(30, 41, 59, 0.5)", border: "1px solid var(--border-subtle)", borderRadius: "8px", padding: "10px 12px" }}>
              <div style={{ fontSize: "10px", fontWeight: "700", color: "var(--text-muted)", textTransform: "uppercase" }}>Payload Mutations</div>
              <div style={{ fontSize: "20px", fontWeight: "800", color: "#cbd5e1", marginTop: "4px" }}>
                {activePlan.total_mutations_attempted || 0}
              </div>
              <div style={{ fontSize: "10px", color: "var(--text-dim)", marginTop: "2px" }}>Adaptive bypasses</div>
            </div>
          </div>

          {/* Source-to-Destination & Cryptographic Evidence Trace */}
          <div
            style={{
              background: "rgba(15, 23, 42, 0.7)",
              border: "1px solid rgba(255, 255, 255, 0.08)",
              borderRadius: "10px",
              padding: "14px 16px",
              marginBottom: "16px",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
              <div style={{ fontSize: "12px", fontWeight: "700", color: "var(--accent-cyan)", display: "flex", alignItems: "center", gap: "6px" }}>
                <span>📡</span> SOURCE-TO-DESTINATION WIRE EXECUTION & EVIDENCE TRACE
              </div>
              <div style={{ display: "flex", gap: "8px" }}>
                <button
                  onClick={() => setActiveTab("chains")}
                  style={{
                    padding: "4px 10px",
                    borderRadius: "6px",
                    background: "rgba(99, 102, 241, 0.2)",
                    border: "1px solid rgba(99, 102, 241, 0.4)",
                    color: "#c7d2fe",
                    fontSize: "11px",
                    fontWeight: "600",
                    cursor: "pointer",
                  }}
                >
                  ⛓️ View Chains ({chains.length})
                </button>
                <button
                  onClick={() => setActiveTab("evidence")}
                  style={{
                    padding: "4px 10px",
                    borderRadius: "6px",
                    background: "rgba(14, 165, 233, 0.2)",
                    border: "1px solid rgba(14, 165, 233, 0.4)",
                    color: "#7dd3fc",
                    fontSize: "11px",
                    fontWeight: "600",
                    cursor: "pointer",
                  }}
                >
                  🔬 View Wire Evidence
                </button>
              </div>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "10px", fontSize: "11px" }}>
              <div style={{ padding: "8px", background: "rgba(30, 41, 59, 0.4)", borderRadius: "6px" }}>
                <span style={{ color: "var(--text-muted)", display: "block" }}>Source Actor:</span>
                <strong style={{ color: "var(--text-main)" }}>Autonomous Security Agent</strong> (Agent Lab)
              </div>
              <div style={{ padding: "8px", background: "rgba(30, 41, 59, 0.4)", borderRadius: "6px" }}>
                <span style={{ color: "var(--text-muted)", display: "block" }}>Target Endpoint:</span>
                <strong style={{ color: "var(--accent-cyan)", fontFamily: "DM Mono, monospace" }}>{activePlan.target_url}</strong>
              </div>
              <div style={{ padding: "8px", background: "rgba(30, 41, 59, 0.4)", borderRadius: "6px" }}>
                <span style={{ color: "var(--text-muted)", display: "block" }}>Wire Transactions:</span>
                <strong style={{ color: "#f8fafc" }}>{activePlan.total_turns_executed} Turns</strong> across {chains.length} Chains
              </div>
              <div style={{ padding: "8px", background: "rgba(30, 41, 59, 0.4)", borderRadius: "6px" }}>
                <span style={{ color: "var(--text-muted)", display: "block" }}>Cryptographic Lineage:</span>
                <span style={{ color: "#4ade80", fontWeight: "700" }}>🔒 HMAC-SHA256 Signed</span>
              </div>
            </div>
          </div>

          {/* Assessed OWASP Risks Summary */}
          <div style={{ marginBottom: "16px" }}>
            <div style={{ fontSize: "12px", fontWeight: "700", color: "var(--text-muted)", marginBottom: "8px", textTransform: "uppercase" }}>
              ASSESSED OWASP RISK OUTCOMES
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: "8px" }}>
              {activePlan.risk_assessments && Object.keys(activePlan.risk_assessments).length > 0 ? (
                Object.entries(activePlan.risk_assessments).map(([rCode, rData]) => {
                  const meta = risksList.find((x) => x.risk_id === rCode) || {};
                  const isVuln = (rData.vulnerable_scenarios || 0) > 0;
                  return (
                    <div
                      key={rCode}
                      style={{
                        background: "rgba(30, 41, 59, 0.4)",
                        border: `1px solid ${isVuln ? "rgba(239, 68, 68, 0.4)" : "rgba(34, 197, 94, 0.3)"}`,
                        borderRadius: "8px",
                        padding: "10px 12px",
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                      }}
                    >
                      <div>
                        <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                          <span style={{ fontWeight: "800", color: "var(--text-main)", fontSize: "13px" }}>{rCode}</span>
                          <span style={{ fontSize: "10px", padding: "1px 5px", borderRadius: "4px", background: meta.category === "OWASP_AGENTIC" ? "rgba(168, 85, 247, 0.2)" : "rgba(59, 130, 246, 0.2)", color: meta.category === "OWASP_AGENTIC" ? "#c084fc" : "#93c5fd" }}>
                            {meta.category === "OWASP_AGENTIC" ? "AGENTIC" : "LLM"}
                          </span>
                        </div>
                        <div style={{ fontSize: "11px", color: "var(--text-dim)", marginTop: "2px" }}>
                          {meta.risk_name || "OWASP Vulnerability"}
                        </div>
                      </div>
                      <div style={{ textAlign: "right" }}>
                        <span
                          style={{
                            padding: "2px 8px",
                            borderRadius: "10px",
                            fontSize: "11px",
                            fontWeight: "700",
                            background: isVuln ? "rgba(239, 68, 68, 0.2)" : "rgba(34, 197, 94, 0.2)",
                            color: isVuln ? "#f87171" : "#4ade80",
                          }}
                        >
                          {isVuln ? "VULNERABLE" : "BLOCKED"}
                        </span>
                        <div style={{ fontSize: "10px", color: "var(--text-muted)", marginTop: "2px" }}>
                          {rData.tested_scenarios || 3} Scenarios Tested
                        </div>
                      </div>
                    </div>
                  );
                })
              ) : (
                selectedRisks.map((rCode) => {
                  const meta = risksList.find((x) => x.risk_id === rCode) || {};
                  return (
                    <div
                      key={rCode}
                      style={{
                        background: "rgba(30, 41, 59, 0.4)",
                        border: "1px solid rgba(34, 197, 94, 0.3)",
                        borderRadius: "8px",
                        padding: "10px 12px",
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                      }}
                    >
                      <div>
                        <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                          <span style={{ fontWeight: "800", color: "var(--text-main)", fontSize: "13px" }}>{rCode}</span>
                          <span style={{ fontSize: "10px", padding: "1px 5px", borderRadius: "4px", background: meta.category === "OWASP_AGENTIC" ? "rgba(168, 85, 247, 0.2)" : "rgba(59, 130, 246, 0.2)", color: meta.category === "OWASP_AGENTIC" ? "#c084fc" : "#93c5fd" }}>
                            {meta.category === "OWASP_AGENTIC" ? "AGENTIC" : "LLM"}
                          </span>
                        </div>
                        <div style={{ fontSize: "11px", color: "var(--text-dim)", marginTop: "2px" }}>
                          {meta.risk_name || "OWASP Vulnerability"}
                        </div>
                      </div>
                      <div style={{ textAlign: "right" }}>
                        <span style={{ padding: "2px 8px", borderRadius: "10px", fontSize: "11px", fontWeight: "700", background: "rgba(34, 197, 94, 0.2)", color: "#4ade80" }}>
                          BLOCKED
                        </span>
                        <div style={{ fontSize: "10px", color: "var(--text-muted)", marginTop: "2px" }}>
                          3 Scenarios Tested
                        </div>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Actionable Code Remediations & Mitigations Accordion */}
          {Object.keys(remediationsMap).length > 0 && (
            <div
              style={{
                background: "rgba(15, 23, 42, 0.7)",
                border: "1px solid rgba(99, 102, 241, 0.3)",
                borderRadius: "10px",
                padding: "14px 16px",
                marginBottom: "16px",
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
                <div style={{ fontSize: "13px", fontWeight: "700", color: "var(--accent-cyan)", display: "flex", alignItems: "center", gap: "6px" }}>
                  <span>🛠️</span> ACTIONABLE REMEDIATIONS & DEFENSIVE SOURCE CONTROLS
                </div>
                {/* Risk Selector Tabs */}
                <div style={{ display: "flex", gap: "4px" }}>
                  {Object.keys(remediationsMap).map((r) => (
                    <button
                      key={r}
                      onClick={() => setExpandedMitigationRisk(r)}
                      style={{
                        padding: "3px 8px",
                        borderRadius: "6px",
                        background: expandedMitigationRisk === r ? "var(--accent-primary)" : "rgba(30, 41, 59, 0.6)",
                        border: "1px solid rgba(99, 102, 241, 0.4)",
                        color: "#ffffff",
                        fontSize: "11px",
                        fontWeight: "700",
                        cursor: "pointer",
                      }}
                    >
                      {r}
                    </button>
                  ))}
                </div>
              </div>

              {expandedMitigationRisk && remediationsMap[expandedMitigationRisk] && (() => {
                const remData = remediationsMap[expandedMitigationRisk];
                const quickText = typeof remData.quick_mitigation === "string"
                  ? remData.quick_mitigation
                  : (remData.quick_mitigation?.description || remData.summary);
                const archText = typeof remData.architectural_fix === "string"
                  ? remData.architectural_fix
                  : (remData.architectural_fix?.best_practice || remData.architectural_fix?.pattern || remData.architectural_recommendation);
                const snippetText = remData.remediation_code_snippet
                  || remData.quick_mitigation?.snippet
                  || remData.architectural_fix?.snippet
                  || remData.code_snippets?.[0]?.snippet;

                return (
                  <div style={{ fontSize: "12px" }}>
                    {remData.title && (
                      <div style={{ fontSize: "13px", fontWeight: "800", color: "#f8fafc", marginBottom: "8px" }}>
                        {remData.title}
                      </div>
                    )}
                    <div style={{ marginBottom: "10px" }}>
                      <div style={{ fontWeight: "700", color: "#f8fafc", marginBottom: "2px" }}>
                        Quick Mitigation:
                      </div>
                      <div style={{ color: "#cbd5e1", lineHeight: "1.5" }}>
                        {quickText}
                      </div>
                    </div>

                    <div style={{ marginBottom: "12px" }}>
                      <div style={{ fontWeight: "700", color: "#f8fafc", marginBottom: "2px" }}>
                        Architectural Recommendation:
                      </div>
                      <div style={{ color: "#94a3b8", lineHeight: "1.5" }}>
                        {archText}
                      </div>
                    </div>

                    {snippetText && (
                      <div style={{ position: "relative", marginBottom: "10px" }}>
                        <div
                          style={{
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "center",
                            background: "#0f172a",
                            padding: "6px 12px",
                            borderTopLeftRadius: "6px",
                            borderTopRightRadius: "6px",
                            border: "1px solid rgba(255, 255, 255, 0.1)",
                            borderBottom: "none",
                          }}
                        >
                          <span style={{ fontSize: "11px", fontFamily: "DM Mono, monospace", color: "var(--accent-cyan)", fontWeight: "700" }}>
                            PYTHON DEFENSIVE CONTROL ({expandedMitigationRisk})
                          </span>
                          <button
                            onClick={() => {
                              navigator.clipboard.writeText(snippetText);
                              setCopiedCodeSnippet(expandedMitigationRisk);
                              setTimeout(() => setCopiedCodeSnippet(null), 2500);
                            }}
                            style={{
                              padding: "2px 8px",
                              borderRadius: "4px",
                              background: "rgba(99, 102, 241, 0.3)",
                              border: "1px solid rgba(99, 102, 241, 0.5)",
                              color: "#ffffff",
                              fontSize: "11px",
                              cursor: "pointer",
                              display: "flex",
                              alignItems: "center",
                              gap: "4px",
                            }}
                          >
                            {copiedCodeSnippet === expandedMitigationRisk ? "✅ Copied" : "📋 Copy Code"}
                          </button>
                        </div>
                        <pre
                          style={{
                            margin: 0,
                            padding: "12px",
                            background: "#020617",
                            border: "1px solid rgba(255, 255, 255, 0.1)",
                            borderBottomLeftRadius: "6px",
                            borderBottomRightRadius: "6px",
                            color: "#38bdf8",
                            fontFamily: "DM Mono, monospace",
                            fontSize: "11px",
                            lineHeight: "1.5",
                            overflowX: "auto",
                          }}
                        >
                          {snippetText}
                        </pre>
                      </div>
                    )}

                    {remData.verification_probe && (
                      <div style={{ padding: "8px 12px", background: "rgba(30, 41, 59, 0.5)", borderRadius: "6px", marginBottom: "8px", fontSize: "11px" }}>
                        <span style={{ fontWeight: "700", color: "var(--accent-cyan)" }}>Verification Probe: </span>
                        <span style={{ color: "var(--text-main)", fontFamily: "DM Mono, monospace" }}>
                          {remData.verification_probe.method} {remData.verification_probe.endpoint} (Expected Status: {remData.verification_probe.expected_status})
                        </span>
                      </div>
                    )}
                  </div>
                );
              })()}
            </div>
          )}

          {/* Direct 1-Click Report Downloads Bar */}
          <div
            style={{
              display: "flex",
              flexWrap: "wrap",
              alignItems: "center",
              justifyContent: "space-between",
              gap: "12px",
              background: "rgba(30, 41, 59, 0.7)",
              border: "1px solid rgba(99, 102, 241, 0.3)",
              borderRadius: "10px",
              padding: "12px 16px",
            }}
          >
            <div>
              <div style={{ fontSize: "12px", fontWeight: "700", color: "#f8fafc", display: "flex", alignItems: "center", gap: "6px" }}>
                <span>📑</span> EXPORT ASSESSMENT ARTIFACTS
              </div>
              <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                Cryptographically signed enterprise audit reports in PDF, XLSX, CSV, and JSON
              </div>
            </div>

            <div style={{ display: "flex", flexWrap: "wrap", gap: "8px" }}>
              <button
                onClick={() => handleDownloadAutonomousReport("pdf")}
                disabled={downloadingFormat === "pdf"}
                style={{
                  padding: "8px 14px",
                  borderRadius: "8px",
                  background: "linear-gradient(135deg, #ef4444, #dc2626)",
                  border: "none",
                  color: "#ffffff",
                  fontSize: "12px",
                  fontWeight: "700",
                  cursor: downloadingFormat === "pdf" ? "wait" : "pointer",
                  display: "flex",
                  alignItems: "center",
                  gap: "6px",
                  boxShadow: "0 2px 8px rgba(239, 68, 68, 0.3)",
                }}
              >
                {downloadingFormat === "pdf" ? "⏳ Generating..." : "📄 Download PDF"}
              </button>

              <button
                onClick={() => handleDownloadAutonomousReport("xlsx")}
                disabled={downloadingFormat === "xlsx"}
                style={{
                  padding: "8px 14px",
                  borderRadius: "8px",
                  background: "linear-gradient(135deg, #10b981, #059669)",
                  border: "none",
                  color: "#ffffff",
                  fontSize: "12px",
                  fontWeight: "700",
                  cursor: downloadingFormat === "xlsx" ? "wait" : "pointer",
                  display: "flex",
                  alignItems: "center",
                  gap: "6px",
                  boxShadow: "0 2px 8px rgba(16, 185, 129, 0.3)",
                }}
              >
                {downloadingFormat === "xlsx" ? "⏳ Generating..." : "📊 Download Excel"}
              </button>

              <button
                onClick={() => handleDownloadAutonomousReport("csv")}
                disabled={downloadingFormat === "csv"}
                style={{
                  padding: "8px 14px",
                  borderRadius: "8px",
                  background: "rgba(59, 130, 246, 0.2)",
                  border: "1px solid rgba(59, 130, 246, 0.5)",
                  color: "#93c5fd",
                  fontSize: "12px",
                  fontWeight: "700",
                  cursor: downloadingFormat === "csv" ? "wait" : "pointer",
                  display: "flex",
                  alignItems: "center",
                  gap: "6px",
                }}
              >
                {downloadingFormat === "csv" ? "⏳ Generating..." : "📋 Download CSV"}
              </button>

              <button
                onClick={() => handleDownloadAutonomousReport("json")}
                disabled={downloadingFormat === "json"}
                style={{
                  padding: "8px 14px",
                  borderRadius: "8px",
                  background: "rgba(148, 163, 184, 0.15)",
                  border: "1px solid rgba(148, 163, 184, 0.3)",
                  color: "#e2e8f0",
                  fontSize: "12px",
                  fontWeight: "700",
                  cursor: downloadingFormat === "json" ? "wait" : "pointer",
                  display: "flex",
                  alignItems: "center",
                  gap: "6px",
                }}
              >
                {downloadingFormat === "json" ? "⏳ Generating..." : "📦 Download JSON"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Phase E9: Persistent Global SOC Context & Mission Control Bar */}
      <div
        style={{
          background: "linear-gradient(135deg, rgba(30, 41, 59, 0.95), rgba(15, 23, 42, 0.98))",
          border: "1px solid var(--border-subtle)",
          borderRadius: "12px",
          padding: "14px 18px",
          marginBottom: "16px",
          display: "flex",
          flexWrap: "wrap",
          justifyContent: "space-between",
          alignItems: "center",
          gap: "12px",
          boxShadow: "0 4px 12px rgba(0,0,0,0.15)",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <span style={{ fontSize: "20px" }}>🏢</span>
            <div>
              <div style={{ fontSize: "14px", fontWeight: "800", color: "#f8fafc", letterSpacing: "0.5px" }}>
                Enterprise SOC Mission Control
              </div>
              <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                Unified Governance across E1–E8 Capabilities
              </div>
            </div>
          </div>

          {/* System Health Badge */}
          <div
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "6px",
              padding: "4px 10px",
              borderRadius: "20px",
              background:
                (socOverviewData?.system_health || "HEALTHY") === "HEALTHY"
                  ? "rgba(34, 197, 94, 0.15)"
                  : (socOverviewData?.system_health === "DEGRADED"
                  ? "rgba(234, 179, 8, 0.15)"
                  : "rgba(239, 68, 68, 0.15)"),
              border: `1px solid ${
                (socOverviewData?.system_health || "HEALTHY") === "HEALTHY"
                  ? "rgba(34, 197, 94, 0.4)"
                  : (socOverviewData?.system_health === "DEGRADED"
                  ? "rgba(234, 179, 8, 0.4)"
                  : "rgba(239, 68, 68, 0.4)")
              }`,
              fontSize: "11px",
              fontWeight: "700",
              color:
                (socOverviewData?.system_health || "HEALTHY") === "HEALTHY"
                  ? "#22c55e"
                  : (socOverviewData?.system_health === "DEGRADED" ? "#eab308" : "#ef4444"),
            }}
          >
            <span
              style={{
                width: "8px",
                height: "8px",
                borderRadius: "50%",
                background:
                  (socOverviewData?.system_health || "HEALTHY") === "HEALTHY"
                    ? "#22c55e"
                    : (socOverviewData?.system_health === "DEGRADED" ? "#eab308" : "#ef4444"),
              }}
            />
            {socOverviewData?.system_health || "HEALTHY"}
          </div>
        </div>

        {/* Active Context Filters */}
        <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
          {/* Target URL indicator */}
          <div
            style={{
              padding: "4px 8px",
              borderRadius: "6px",
              background: "var(--bg-primary)",
              border: "1px solid var(--border-subtle)",
              fontSize: "11px",
              fontFamily: "DM Mono, monospace",
              color: "var(--accent-cyan)",
            }}
          >
            🎯 {targetUrl || "http://127.0.0.1:8000"}
          </div>

          {/* Session Filter */}
          <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
            <span style={{ fontSize: "11px", color: "var(--text-dim)" }}>Session:</span>
            <input
              type="text"
              placeholder="All sessions"
              value={sharedSessionFilter}
              onChange={(e) => setSharedSessionFilter(e.target.value)}
              style={{
                width: "120px",
                padding: "3px 6px",
                borderRadius: "4px",
                background: "var(--bg-primary)",
                border: "1px solid var(--border-subtle)",
                color: "var(--text-main)",
                fontSize: "11px",
                fontFamily: "DM Mono, monospace",
              }}
            />
            {sharedSessionFilter && (
              <button
                onClick={() => setSharedSessionFilter("")}
                style={{ background: "transparent", border: "none", color: "var(--text-dim)", cursor: "pointer", fontSize: "11px" }}
                title="Clear Session Filter"
              >
                ✕
              </button>
            )}
          </div>

          {/* Plan Filter */}
          <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
            <span style={{ fontSize: "11px", color: "var(--text-dim)" }}>Plan:</span>
            <input
              type="text"
              placeholder="All plans"
              value={sharedPlanFilter}
              onChange={(e) => setSharedPlanFilter(e.target.value)}
              style={{
                width: "110px",
                padding: "3px 6px",
                borderRadius: "4px",
                background: "var(--bg-primary)",
                border: "1px solid var(--border-subtle)",
                color: "var(--text-main)",
                fontSize: "11px",
                fontFamily: "DM Mono, monospace",
              }}
            />
            {sharedPlanFilter && (
              <button
                onClick={() => setSharedPlanFilter("")}
                style={{ background: "transparent", border: "none", color: "var(--text-dim)", cursor: "pointer", fontSize: "11px" }}
                title="Clear Plan Filter"
              >
                ✕
              </button>
            )}
          </div>

          {/* Finding Filter */}
          <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
            <span style={{ fontSize: "11px", color: "var(--text-dim)" }}>Finding:</span>
            <input
              type="text"
              placeholder="All findings"
              value={sharedFindingFilter}
              onChange={(e) => setSharedFindingFilter(e.target.value)}
              style={{
                width: "110px",
                padding: "3px 6px",
                borderRadius: "4px",
                background: "var(--bg-primary)",
                border: "1px solid var(--border-subtle)",
                color: "var(--text-main)",
                fontSize: "11px",
                fontFamily: "DM Mono, monospace",
              }}
            />
            {sharedFindingFilter && (
              <button
                onClick={() => setSharedFindingFilter("")}
                style={{ background: "transparent", border: "none", color: "var(--text-dim)", cursor: "pointer", fontSize: "11px" }}
                title="Clear Finding Filter"
              >
                ✕
              </button>
            )}
          </div>

          {/* Sync & Clear Actions */}
          <button
            onClick={handleFetchSocOverview}
            disabled={isFetchingSocOverview}
            style={{
              padding: "5px 12px",
              borderRadius: "6px",
              background: "var(--accent-primary)",
              color: "#ffffff",
              border: "none",
              fontSize: "11px",
              fontWeight: "700",
              cursor: isFetchingSocOverview ? "not-allowed" : "pointer",
              display: "flex",
              alignItems: "center",
              gap: "4px",
            }}
          >
            {isFetchingSocOverview ? "🔄 Syncing..." : "🔄 Sync SOC"}
          </button>

          {(sharedSessionFilter || sharedPlanFilter || sharedFindingFilter) && (
            <button
              onClick={() => {
                setSharedSessionFilter("");
                setSharedPlanFilter("");
                setSharedFindingFilter("");
              }}
              style={{
                padding: "5px 10px",
                borderRadius: "6px",
                background: "rgba(239, 68, 68, 0.2)",
                color: "var(--color-error)",
                border: "1px solid rgba(239, 68, 68, 0.4)",
                fontSize: "11px",
                fontWeight: "600",
                cursor: "pointer",
              }}
            >
              Reset Filters
            </button>
          )}
        </div>
      </div>

      {/* Main Results Container: Tabs & Views */}
      <div
        id="main-tabs-container"
        data-testid="main-tabs-container"
        style={{ background: "var(--bg-surface)", border: "1px solid var(--border-subtle)", borderRadius: "12px", overflow: "hidden" }}
      >
        {/* Navigation Tabs Header */}
        <div style={{ borderBottom: "1px solid var(--border-subtle)", background: "var(--bg-surface-elevated)" }}>
          {/* Primary Row: Enterprise SOC Capability Suite (E1–E8) */}
          <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", borderBottom: "1px solid rgba(255,255,255,0.06)", padding: "0 8px" }}>
            <div style={{ padding: "8px 12px", fontSize: "11px", fontWeight: "800", color: "var(--accent-cyan)", letterSpacing: "0.5px", textTransform: "uppercase", display: "flex", alignItems: "center", gap: "6px" }}>
              <span>🏢</span> SOC SUITE
            </div>

            <button
              onClick={() => setActiveTab("soc_overview")}
              style={{
                padding: "10px 14px",
                background: activeTab === "soc_overview" ? "var(--bg-surface)" : "transparent",
                color: activeTab === "soc_overview" ? "var(--accent-cyan)" : "var(--text-muted)",
                border: "none",
                borderBottom: activeTab === "soc_overview" ? "2px solid var(--accent-cyan)" : "none",
                fontSize: "12px",
                fontWeight: activeTab === "soc_overview" ? "700" : "600",
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                gap: "6px",
              }}
            >
              🌐 Mission Control
            </button>

            <button
              onClick={() => setActiveTab("intelligence")}
              style={{
                padding: "10px 14px",
                background: activeTab === "intelligence" ? "var(--bg-surface)" : "transparent",
                color: activeTab === "intelligence" ? "var(--accent-cyan)" : "var(--text-muted)",
                border: "none",
                borderBottom: activeTab === "intelligence" ? "2px solid var(--accent-cyan)" : "none",
                fontSize: "12px",
                fontWeight: activeTab === "intelligence" ? "700" : "600",
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                gap: "6px",
              }}
            >
              🧠 E1: Intelligence
            </button>

            <button
              onClick={() => setActiveTab("attack_graph")}
              style={{
                padding: "10px 14px",
                background: activeTab === "attack_graph" ? "var(--bg-surface)" : "transparent",
                color: activeTab === "attack_graph" ? "var(--accent-cyan)" : "var(--text-muted)",
                border: "none",
                borderBottom: activeTab === "attack_graph" ? "2px solid var(--accent-cyan)" : "none",
                fontSize: "12px",
                fontWeight: activeTab === "attack_graph" ? "700" : "600",
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                gap: "6px",
              }}
            >
              🕸️ E2: Attack Graph
            </button>

            <button
              onClick={() => setActiveTab("schema_intelligence")}
              style={{
                padding: "10px 14px",
                background: activeTab === "schema_intelligence" ? "var(--bg-surface)" : "transparent",
                color: activeTab === "schema_intelligence" ? "var(--accent-cyan)" : "var(--text-muted)",
                border: "none",
                borderBottom: activeTab === "schema_intelligence" ? "2px solid var(--accent-cyan)" : "none",
                fontSize: "12px",
                fontWeight: activeTab === "schema_intelligence" ? "700" : "600",
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                gap: "6px",
              }}
            >
              📜 E3: Schema
            </button>

            <button
              onClick={() => setActiveTab("lifecycle")}
              style={{
                padding: "10px 14px",
                background: activeTab === "lifecycle" ? "var(--bg-surface)" : "transparent",
                color: activeTab === "lifecycle" ? "var(--accent-cyan)" : "var(--text-muted)",
                border: "none",
                borderBottom: activeTab === "lifecycle" ? "2px solid var(--accent-cyan)" : "none",
                fontSize: "12px",
                fontWeight: activeTab === "lifecycle" ? "700" : "600",
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                gap: "6px",
              }}
            >
              📋 E4: Finding Lifecycle
            </button>

            <button
              onClick={() => setActiveTab("regression")}
              style={{
                padding: "10px 14px",
                background: activeTab === "regression" ? "var(--bg-surface)" : "transparent",
                color: activeTab === "regression" ? "var(--accent-cyan)" : "var(--text-muted)",
                border: "none",
                borderBottom: activeTab === "regression" ? "2px solid var(--accent-cyan)" : "none",
                fontSize: "12px",
                fontWeight: activeTab === "regression" ? "700" : "600",
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                gap: "6px",
              }}
            >
              🔄 E5: Regression
            </button>

            <button
              onClick={() => setActiveTab("enterprise_reporting")}
              style={{
                padding: "10px 14px",
                background: activeTab === "enterprise_reporting" ? "var(--bg-surface)" : "transparent",
                color: activeTab === "enterprise_reporting" ? "var(--accent-cyan)" : "var(--text-muted)",
                border: "none",
                borderBottom: activeTab === "enterprise_reporting" ? "2px solid var(--accent-cyan)" : "none",
                fontSize: "12px",
                fontWeight: activeTab === "enterprise_reporting" ? "700" : "600",
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                gap: "6px",
              }}
            >
              📑 E6: Reporting
            </button>

            <button
              onClick={() => setActiveTab("explainability")}
              style={{
                padding: "10px 14px",
                background: activeTab === "explainability" ? "var(--bg-surface)" : "transparent",
                color: activeTab === "explainability" ? "var(--accent-cyan)" : "var(--text-muted)",
                border: "none",
                borderBottom: activeTab === "explainability" ? "2px solid var(--accent-cyan)" : "none",
                fontSize: "12px",
                fontWeight: activeTab === "explainability" ? "700" : "600",
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                gap: "6px",
              }}
            >
              ⚖️ E7: Decisions
            </button>

            <button
              onClick={() => setActiveTab("operations")}
              style={{
                padding: "10px 14px",
                background: activeTab === "operations" ? "var(--bg-surface)" : "transparent",
                color: activeTab === "operations" ? "var(--accent-cyan)" : "var(--text-muted)",
                border: "none",
                borderBottom: activeTab === "operations" ? "2px solid var(--accent-cyan)" : "none",
                fontSize: "12px",
                fontWeight: activeTab === "operations" ? "700" : "600",
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                gap: "6px",
              }}
            >
              ⚡ E8: Operations
            </button>

            <button
              id="tab-btn-claude-code"
              data-testid="tab-btn-claude-code"
              type="button"
              onClick={() => setActiveTab("claude_code")}
              style={{
                padding: "10px 14px",
                background: activeTab === "claude_code" ? "rgba(168, 85, 247, 0.15)" : "transparent",
                color: activeTab === "claude_code" ? "#c084fc" : "#a855f7",
                border: "none",
                borderBottom: activeTab === "claude_code" ? "2px solid #a855f7" : "none",
                fontSize: "12px",
                fontWeight: activeTab === "claude_code" ? "700" : "600",
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                gap: "6px",
                pointerEvents: "auto",
              }}
            >
              🛡️ Claude Code Audit
            </button>
          </div>

          {/* Secondary Row: Diagnostic Probing Labs */}
          <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", padding: "0 8px", background: "rgba(0,0,0,0.15)" }}>
            <div style={{ padding: "6px 12px", fontSize: "10px", fontWeight: "700", color: "var(--text-dim)", letterSpacing: "0.5px", textTransform: "uppercase" }}>
              🔬 DIAGNOSTIC LABS:
            </div>

            <button
              onClick={() => setActiveTab("chains")}
              style={{
                padding: "6px 12px",
                background: activeTab === "chains" ? "var(--bg-surface)" : "transparent",
                color: activeTab === "chains" ? "var(--accent-cyan)" : "var(--text-muted)",
                border: "none",
                borderBottom: activeTab === "chains" ? "2px solid var(--accent-cyan)" : "none",
                fontSize: "11px",
                fontWeight: "600",
                cursor: "pointer",
              }}
            >
              ⛓️ Chains ({chains.length})
            </button>

            <button
              onClick={() => setActiveTab("mutations")}
              style={{
                padding: "6px 12px",
                background: activeTab === "mutations" ? "var(--bg-surface)" : "transparent",
                color: activeTab === "mutations" ? "var(--accent-cyan)" : "var(--text-muted)",
                border: "none",
                borderBottom: activeTab === "mutations" ? "2px solid var(--accent-cyan)" : "none",
                fontSize: "11px",
                fontWeight: "600",
                cursor: "pointer",
              }}
            >
              🧬 Mutations ({mutations.length})
            </button>

            <button
              onClick={() => setActiveTab("evidence")}
              style={{
                padding: "6px 12px",
                background: activeTab === "evidence" ? "var(--bg-surface)" : "transparent",
                color: activeTab === "evidence" ? "var(--accent-cyan)" : "var(--text-muted)",
                border: "none",
                borderBottom: activeTab === "evidence" ? "2px solid var(--accent-cyan)" : "none",
                fontSize: "11px",
                fontWeight: "600",
                cursor: "pointer",
              }}
            >
              🔎 Evidence
            </button>

            <button
              onClick={() => setActiveTab("report")}
              style={{
                padding: "6px 12px",
                background: activeTab === "report" ? "var(--bg-surface)" : "transparent",
                color: activeTab === "report" ? "var(--accent-cyan)" : "var(--text-muted)",
                border: "none",
                borderBottom: activeTab === "report" ? "2px solid var(--accent-cyan)" : "none",
                fontSize: "11px",
                fontWeight: "600",
                cursor: "pointer",
              }}
            >
              📑 Assessment
            </button>

            <button
              onClick={() => setActiveTab("context")}
              style={{
                padding: "6px 12px",
                background: activeTab === "context" ? "var(--bg-surface)" : "transparent",
                color: activeTab === "context" ? "var(--accent-cyan)" : "var(--text-muted)",
                border: "none",
                borderBottom: activeTab === "context" ? "2px solid var(--accent-cyan)" : "none",
                fontSize: "11px",
                fontWeight: "600",
                cursor: "pointer",
              }}
            >
              🌐 Recon
            </button>

            <button
              onClick={() => setActiveTab("correlation")}
              style={{
                padding: "6px 12px",
                background: activeTab === "correlation" ? "var(--bg-surface)" : "transparent",
                color: activeTab === "correlation" ? "var(--accent-cyan)" : "var(--text-muted)",
                border: "none",
                borderBottom: activeTab === "correlation" ? "2px solid var(--accent-cyan)" : "none",
                fontSize: "11px",
                fontWeight: "600",
                cursor: "pointer",
              }}
            >
              🕸️ OWASP Graph
            </button>

            <button
              onClick={() => setActiveTab("attack_chains")}
              style={{
                padding: "6px 12px",
                background: activeTab === "attack_chains" ? "var(--bg-surface)" : "transparent",
                color: activeTab === "attack_chains" ? "var(--accent-cyan)" : "var(--text-muted)",
                border: "none",
                borderBottom: activeTab === "attack_chains" ? "2px solid var(--accent-cyan)" : "none",
                fontSize: "11px",
                fontWeight: "600",
                cursor: "pointer",
              }}
            >
              ⚡ Multi-Risk
            </button>

            <button
              onClick={() => setActiveTab("rca_remediation")}
              style={{
                padding: "6px 12px",
                background: activeTab === "rca_remediation" ? "var(--bg-surface)" : "transparent",
                color: activeTab === "rca_remediation" ? "var(--accent-cyan)" : "var(--text-muted)",
                border: "none",
                borderBottom: activeTab === "rca_remediation" ? "2px solid var(--accent-cyan)" : "none",
                fontSize: "11px",
                fontWeight: "600",
                cursor: "pointer",
              }}
            >
              🔬 RCA & Remediation
            </button>
          </div>
        </div>

        {/* Tab Content View */}
        <div style={{ padding: "20px" }}>
          {/* TAB 0: Phase E9 Enterprise SOC Overview & Mission Control Cockpit */}
          {activeTab === "soc_overview" && (
            <div>
              {/* Mission Control Cockpit Header */}
              <div
                style={{
                  background: "var(--bg-surface-elevated)",
                  borderRadius: "10px",
                  border: "1px solid var(--border-subtle)",
                  padding: "18px 20px",
                  marginBottom: "20px",
                  display: "flex",
                  flexWrap: "wrap",
                  justifyContent: "space-between",
                  alignItems: "center",
                  gap: "14px",
                }}
              >
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "4px" }}>
                    <span style={{ fontSize: "22px" }}>🌐</span>
                    <h2 style={{ fontSize: "16px", fontWeight: "800", color: "var(--text-main)", margin: 0 }}>
                      ApexShield Enterprise Security Operations Center (SOC)
                    </h2>
                    <span
                      style={{
                        padding: "2px 8px",
                        borderRadius: "10px",
                        fontSize: "10px",
                        fontWeight: "700",
                        background:
                          (socOverviewData?.system_health || "HEALTHY") === "HEALTHY"
                            ? "rgba(34,197,94,0.15)"
                            : "rgba(239,68,68,0.15)",
                        color:
                          (socOverviewData?.system_health || "HEALTHY") === "HEALTHY" ? "#22c55e" : "#ef4444",
                        border: `1px solid ${
                          (socOverviewData?.system_health || "HEALTHY") === "HEALTHY"
                            ? "rgba(34,197,94,0.3)"
                            : "rgba(239,68,68,0.3)"
                        }`,
                      }}
                    >
                      {socOverviewData?.system_health || "HEALTHY"}
                    </span>
                  </div>
                  <div style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                    Real-time operational orchestration and governance across all eight Phase E capabilities (E1–E8).
                  </div>
                </div>

                <div style={{ display: "flex", alignItems: "center", gap: "12px", fontSize: "11px", color: "var(--text-dim)" }}>
                  <div>
                    <strong>Trace ID:</strong>{" "}
                    <span style={{ fontFamily: "DM Mono, monospace", color: "var(--accent-cyan)" }}>
                      {socOverviewData?.execution_trace_id || "TRC-SOC-INIT"}
                    </span>
                  </div>
                  <div>•</div>
                  <div>
                    <strong>Last Synced:</strong>{" "}
                    <span>
                      {socOverviewData?.timestamp
                        ? new Date(socOverviewData.timestamp).toLocaleTimeString()
                        : "Ready"}
                    </span>
                  </div>
                  <button
                    onClick={handleFetchSocOverview}
                    disabled={isFetchingSocOverview}
                    style={{
                      padding: "6px 12px",
                      borderRadius: "6px",
                      background: "var(--accent-primary)",
                      color: "#fff",
                      border: "none",
                      fontSize: "11px",
                      fontWeight: "700",
                      cursor: "pointer",
                    }}
                  >
                    {isFetchingSocOverview ? "Syncing..." : "Refresh Status"}
                  </button>
                </div>
              </div>

              {/* 8-Card Enterprise Capabilities Grid */}
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
                  gap: "16px",
                  marginBottom: "20px",
                }}
              >
                {/* Card 1: E1 Dynamic Security Intelligence */}
                <div
                  style={{
                    background: "var(--bg-surface)",
                    borderRadius: "10px",
                    border: "1px solid var(--border-subtle)",
                    padding: "16px",
                    display: "flex",
                    flexDirection: "column",
                    justifyContent: "space-between",
                  }}
                >
                  <div>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                      <span style={{ fontSize: "12px", fontWeight: "800", color: "var(--accent-cyan)", display: "flex", alignItems: "center", gap: "6px" }}>
                        🧠 E1 · Dynamic Intelligence
                      </span>
                      <span style={{ fontSize: "10px", fontWeight: "700", padding: "2px 6px", borderRadius: "4px", background: "rgba(34,197,94,0.15)", color: "#22c55e" }}>
                        ACTIVE
                      </span>
                    </div>
                    <div style={{ fontSize: "11px", color: "var(--text-muted)", marginBottom: "12px" }}>
                      Dynamic threat profiling and historical vulnerability posture tracking.
                    </div>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px", marginBottom: "12px" }}>
                      <div style={{ background: "var(--bg-surface-elevated)", padding: "8px", borderRadius: "6px" }}>
                        <div style={{ fontSize: "10px", color: "var(--text-dim)" }}>Cataloged Risks</div>
                        <div style={{ fontSize: "16px", fontWeight: "800", color: "var(--text-main)" }}>
                          {socOverviewData?.capabilities?.e1_intelligence?.total_risks_cataloged ?? 20}
                        </div>
                      </div>
                      <div style={{ background: "var(--bg-surface-elevated)", padding: "8px", borderRadius: "6px" }}>
                        <div style={{ fontSize: "10px", color: "var(--text-dim)" }}>High Priority</div>
                        <div style={{ fontSize: "16px", fontWeight: "800", color: "var(--color-danger, #ef4444)" }}>
                          {socOverviewData?.capabilities?.e1_intelligence?.priority_distribution?.HIGH ?? 0}
                        </div>
                      </div>
                    </div>
                  </div>
                  <button
                    onClick={() => navigateToSocView("intelligence")}
                    style={{
                      width: "100%",
                      padding: "8px",
                      borderRadius: "6px",
                      background: "rgba(99,102,241,0.15)",
                      color: "var(--accent-primary)",
                      border: "1px solid rgba(99,102,241,0.3)",
                      fontSize: "11px",
                      fontWeight: "700",
                      cursor: "pointer",
                      textAlign: "center",
                    }}
                  >
                    Open Intelligence View →
                  </button>
                </div>

                {/* Card 2: E2 Advanced Attack Graph Planning */}
                <div
                  style={{
                    background: "var(--bg-surface)",
                    borderRadius: "10px",
                    border: "1px solid var(--border-subtle)",
                    padding: "16px",
                    display: "flex",
                    flexDirection: "column",
                    justifyContent: "space-between",
                  }}
                >
                  <div>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                      <span style={{ fontSize: "12px", fontWeight: "800", color: "var(--accent-cyan)", display: "flex", alignItems: "center", gap: "6px" }}>
                        🕸️ E2 · Attack Graph Planning
                      </span>
                      <span style={{ fontSize: "10px", fontWeight: "700", padding: "2px 6px", borderRadius: "4px", background: "rgba(34,197,94,0.15)", color: "#22c55e" }}>
                        ACTIVE
                      </span>
                    </div>
                    <div style={{ fontSize: "11px", color: "var(--text-muted)", marginBottom: "12px" }}>
                      Multi-stage attack graph generation and cyclic escalation loop detection.
                    </div>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px", marginBottom: "12px" }}>
                      <div style={{ background: "var(--bg-surface-elevated)", padding: "8px", borderRadius: "6px" }}>
                        <div style={{ fontSize: "10px", color: "var(--text-dim)" }}>Graph Nodes / Edges</div>
                        <div style={{ fontSize: "14px", fontWeight: "800", color: "var(--text-main)" }}>
                          {socOverviewData?.capabilities?.e2_attack_graph?.graph_nodes_count ?? 0} /{" "}
                          {socOverviewData?.capabilities?.e2_attack_graph?.graph_edges_count ?? 0}
                        </div>
                      </div>
                      <div style={{ background: "var(--bg-surface-elevated)", padding: "8px", borderRadius: "6px" }}>
                        <div style={{ fontSize: "10px", color: "var(--text-dim)" }}>Cyclic Loops</div>
                        <div style={{ fontSize: "14px", fontWeight: "800", color: socOverviewData?.capabilities?.e2_attack_graph?.has_cycles ? "var(--color-warning, #eab308)" : "var(--color-success, #22c55e)" }}>
                          {socOverviewData?.capabilities?.e2_attack_graph?.has_cycles ? "Cycles Detected" : "Acyclic DAG"}
                        </div>
                      </div>
                    </div>
                  </div>
                  <button
                    onClick={() => navigateToSocView("attack_graph")}
                    style={{
                      width: "100%",
                      padding: "8px",
                      borderRadius: "6px",
                      background: "rgba(99,102,241,0.15)",
                      color: "var(--accent-primary)",
                      border: "1px solid rgba(99,102,241,0.3)",
                      fontSize: "11px",
                      fontWeight: "700",
                      cursor: "pointer",
                      textAlign: "center",
                    }}
                  >
                    Explore Attack Graphs →
                  </button>
                </div>

                {/* Card 3: E3 Deep OpenAPI Schema Intelligence */}
                <div
                  style={{
                    background: "var(--bg-surface)",
                    borderRadius: "10px",
                    border: "1px solid var(--border-subtle)",
                    padding: "16px",
                    display: "flex",
                    flexDirection: "column",
                    justifyContent: "space-between",
                  }}
                >
                  <div>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                      <span style={{ fontSize: "12px", fontWeight: "800", color: "var(--accent-cyan)", display: "flex", alignItems: "center", gap: "6px" }}>
                        📜 E3 · Schema Intelligence
                      </span>
                      <span style={{ fontSize: "10px", fontWeight: "700", padding: "2px 6px", borderRadius: "4px", background: "rgba(34,197,94,0.15)", color: "#22c55e" }}>
                        ACTIVE
                      </span>
                    </div>
                    <div style={{ fontSize: "11px", color: "var(--text-muted)", marginBottom: "12px" }}>
                      Deep endpoint parameter mutation and automated boundary test planning.
                    </div>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px", marginBottom: "12px" }}>
                      <div style={{ background: "var(--bg-surface-elevated)", padding: "8px", borderRadius: "6px" }}>
                        <div style={{ fontSize: "10px", color: "var(--text-dim)" }}>Inferred Endpoints</div>
                        <div style={{ fontSize: "16px", fontWeight: "800", color: "var(--text-main)" }}>
                          {socOverviewData?.capabilities?.e3_schema_intelligence?.inferred_endpoints_count ?? 0}
                        </div>
                      </div>
                      <div style={{ background: "var(--bg-surface-elevated)", padding: "8px", borderRadius: "6px" }}>
                        <div style={{ fontSize: "10px", color: "var(--text-dim)" }}>Parameter Mutations</div>
                        <div style={{ fontSize: "16px", fontWeight: "800", color: "var(--text-main)" }}>
                          {socOverviewData?.capabilities?.e3_schema_intelligence?.parameter_mutations_count ?? 0}
                        </div>
                      </div>
                    </div>
                  </div>
                  <button
                    onClick={() => navigateToSocView("schema_intelligence")}
                    style={{
                      width: "100%",
                      padding: "8px",
                      borderRadius: "6px",
                      background: "rgba(99,102,241,0.15)",
                      color: "var(--accent-primary)",
                      border: "1px solid rgba(99,102,241,0.3)",
                      fontSize: "11px",
                      fontWeight: "700",
                      cursor: "pointer",
                      textAlign: "center",
                    }}
                  >
                    Inspect Schema Analysis →
                  </button>
                </div>

                {/* Card 4: E4 Vulnerability & Evidence Lifecycle */}
                <div
                  style={{
                    background: "var(--bg-surface)",
                    borderRadius: "10px",
                    border: "1px solid var(--border-subtle)",
                    padding: "16px",
                    display: "flex",
                    flexDirection: "column",
                    justifyContent: "space-between",
                  }}
                >
                  <div>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                      <span style={{ fontSize: "12px", fontWeight: "800", color: "var(--accent-cyan)", display: "flex", alignItems: "center", gap: "6px" }}>
                        📋 E4 · Finding Lifecycle
                      </span>
                      <span style={{ fontSize: "10px", fontWeight: "700", padding: "2px 6px", borderRadius: "4px", background: "rgba(34,197,94,0.15)", color: "#22c55e" }}>
                        ACTIVE
                      </span>
                    </div>
                    <div style={{ fontSize: "11px", color: "var(--text-muted)", marginBottom: "12px" }}>
                      Kanban state management and cryptographic evidence tracking across 7 states.
                    </div>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px", marginBottom: "12px" }}>
                      <div style={{ background: "var(--bg-surface-elevated)", padding: "8px", borderRadius: "6px" }}>
                        <div style={{ fontSize: "10px", color: "var(--text-dim)" }}>Open Findings</div>
                        <div style={{ fontSize: "16px", fontWeight: "800", color: "var(--color-warning, #eab308)" }}>
                          {socOverviewData?.capabilities?.e4_finding_lifecycle?.open_findings ?? 0}
                        </div>
                      </div>
                      <div style={{ background: "var(--bg-surface-elevated)", padding: "8px", borderRadius: "6px" }}>
                        <div style={{ fontSize: "10px", color: "var(--text-dim)" }}>Total Findings</div>
                        <div style={{ fontSize: "16px", fontWeight: "800", color: "var(--text-main)" }}>
                          {socOverviewData?.capabilities?.e4_finding_lifecycle?.total_findings ?? 0}
                        </div>
                      </div>
                    </div>
                  </div>
                  <button
                    onClick={() => navigateToSocView("lifecycle")}
                    style={{
                      width: "100%",
                      padding: "8px",
                      borderRadius: "6px",
                      background: "rgba(99,102,241,0.15)",
                      color: "var(--accent-primary)",
                      border: "1px solid rgba(99,102,241,0.3)",
                      fontSize: "11px",
                      fontWeight: "700",
                      cursor: "pointer",
                      textAlign: "center",
                    }}
                  >
                    Open Kanban Board →
                  </button>
                </div>

                {/* Card 5: E5 Security Regression Intelligence */}
                <div
                  style={{
                    background: "var(--bg-surface)",
                    borderRadius: "10px",
                    border: "1px solid var(--border-subtle)",
                    padding: "16px",
                    display: "flex",
                    flexDirection: "column",
                    justifyContent: "space-between",
                  }}
                >
                  <div>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                      <span style={{ fontSize: "12px", fontWeight: "800", color: "var(--accent-cyan)", display: "flex", alignItems: "center", gap: "6px" }}>
                        🔄 E5 · Regression Intelligence
                      </span>
                      <span style={{ fontSize: "10px", fontWeight: "700", padding: "2px 6px", borderRadius: "4px", background: "rgba(34,197,94,0.15)", color: "#22c55e" }}>
                        ACTIVE
                      </span>
                    </div>
                    <div style={{ fontSize: "11px", color: "var(--text-muted)", marginBottom: "12px" }}>
                      Plan-to-plan diff engine and security posture drift classification.
                    </div>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px", marginBottom: "12px" }}>
                      <div style={{ background: "var(--bg-surface-elevated)", padding: "8px", borderRadius: "6px" }}>
                        <div style={{ fontSize: "10px", color: "var(--text-dim)" }}>Comparisons</div>
                        <div style={{ fontSize: "16px", fontWeight: "800", color: "var(--text-main)" }}>
                          {socOverviewData?.capabilities?.e5_regression_intelligence?.historical_comparisons ?? 0}
                        </div>
                      </div>
                      <div style={{ background: "var(--bg-surface-elevated)", padding: "8px", borderRadius: "6px" }}>
                        <div style={{ fontSize: "10px", color: "var(--text-dim)" }}>Latest Verdict</div>
                        <div style={{ fontSize: "12px", fontWeight: "800", color: "var(--color-success, #22c55e)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {socOverviewData?.capabilities?.e5_regression_intelligence?.latest_comparison_verdict || "NO_REGRESSION"}
                        </div>
                      </div>
                    </div>
                  </div>
                  <button
                    onClick={() => navigateToSocView("regression")}
                    style={{
                      width: "100%",
                      padding: "8px",
                      borderRadius: "6px",
                      background: "rgba(99,102,241,0.15)",
                      color: "var(--accent-primary)",
                      border: "1px solid rgba(99,102,241,0.3)",
                      fontSize: "11px",
                      fontWeight: "700",
                      cursor: "pointer",
                      textAlign: "center",
                    }}
                  >
                    Compare Regression Plans →
                  </button>
                </div>

                {/* Card 6: E6 Enterprise Reporting Engine */}
                <div
                  style={{
                    background: "var(--bg-surface)",
                    borderRadius: "10px",
                    border: "1px solid var(--border-subtle)",
                    padding: "16px",
                    display: "flex",
                    flexDirection: "column",
                    justifyContent: "space-between",
                  }}
                >
                  <div>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                      <span style={{ fontSize: "12px", fontWeight: "800", color: "var(--accent-cyan)", display: "flex", alignItems: "center", gap: "6px" }}>
                        📑 E6 · Enterprise Reporting
                      </span>
                      <span style={{ fontSize: "10px", fontWeight: "700", padding: "2px 6px", borderRadius: "4px", background: "rgba(34,197,94,0.15)", color: "#22c55e" }}>
                        ACTIVE
                      </span>
                    </div>
                    <div style={{ fontSize: "11px", color: "var(--text-muted)", marginBottom: "12px" }}>
                      10-section enterprise reports with HMAC-SHA256 authenticity and multi-format export.
                    </div>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px", marginBottom: "12px" }}>
                      <div style={{ background: "var(--bg-surface-elevated)", padding: "8px", borderRadius: "6px" }}>
                        <div style={{ fontSize: "10px", color: "var(--text-dim)" }}>Archived Reports</div>
                        <div style={{ fontSize: "16px", fontWeight: "800", color: "var(--text-main)" }}>
                          {socOverviewData?.capabilities?.e6_enterprise_reporting?.archived_reports ?? 0}
                        </div>
                      </div>
                      <div style={{ background: "var(--bg-surface-elevated)", padding: "8px", borderRadius: "6px" }}>
                        <div style={{ fontSize: "10px", color: "var(--text-dim)" }}>Manifest Formats</div>
                        <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--text-main)" }}>
                          PDF, XLSX, CSV, JSON
                        </div>
                      </div>
                    </div>
                  </div>
                  <button
                    onClick={() => navigateToSocView("enterprise_reporting")}
                    style={{
                      width: "100%",
                      padding: "8px",
                      borderRadius: "6px",
                      background: "rgba(99,102,241,0.15)",
                      color: "var(--accent-primary)",
                      border: "1px solid rgba(99,102,241,0.3)",
                      fontSize: "11px",
                      fontWeight: "700",
                      cursor: "pointer",
                      textAlign: "center",
                    }}
                  >
                    View Enterprise Reports →
                  </button>
                </div>

                {/* Card 7: E7 Explainable Decision Engine */}
                <div
                  style={{
                    background: "var(--bg-surface)",
                    borderRadius: "10px",
                    border: "1px solid var(--border-subtle)",
                    padding: "16px",
                    display: "flex",
                    flexDirection: "column",
                    justifyContent: "space-between",
                  }}
                >
                  <div>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                      <span style={{ fontSize: "12px", fontWeight: "800", color: "var(--accent-cyan)", display: "flex", alignItems: "center", gap: "6px" }}>
                        ⚖️ E7 · Decision Explainability
                      </span>
                      <span style={{ fontSize: "10px", fontWeight: "700", padding: "2px 6px", borderRadius: "4px", background: "rgba(34,197,94,0.15)", color: "#22c55e" }}>
                        ACTIVE
                      </span>
                    </div>
                    <div style={{ fontSize: "11px", color: "var(--text-muted)", marginBottom: "12px" }}>
                      Explainable autonomous reasoning traces across seven decision types with credential redaction.
                    </div>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px", marginBottom: "12px" }}>
                      <div style={{ background: "var(--bg-surface-elevated)", padding: "8px", borderRadius: "6px" }}>
                        <div style={{ fontSize: "10px", color: "var(--text-dim)" }}>Persisted Decisions</div>
                        <div style={{ fontSize: "16px", fontWeight: "800", color: "var(--text-main)" }}>
                          {socOverviewData?.capabilities?.e7_decision_explainability?.persisted_decisions ?? 0}
                        </div>
                      </div>
                      <div style={{ background: "var(--bg-surface-elevated)", padding: "8px", borderRadius: "6px" }}>
                        <div style={{ fontSize: "10px", color: "var(--text-dim)" }}>Avg Confidence</div>
                        <div style={{ fontSize: "16px", fontWeight: "800", color: "var(--accent-cyan)" }}>
                          {((socOverviewData?.capabilities?.e7_decision_explainability?.average_confidence ?? 0.85) * 100).toFixed(0)}%
                        </div>
                      </div>
                    </div>
                  </div>
                  <button
                    onClick={() => navigateToSocView("explainability")}
                    style={{
                      width: "100%",
                      padding: "8px",
                      borderRadius: "6px",
                      background: "rgba(99,102,241,0.15)",
                      color: "var(--accent-primary)",
                      border: "1px solid rgba(99,102,241,0.3)",
                      fontSize: "11px",
                      fontWeight: "700",
                      cursor: "pointer",
                      textAlign: "center",
                    }}
                  >
                    Inspect Decision Traces →
                  </button>
                </div>

                {/* Card 8: E8 Operations Monitoring & Telemetry */}
                <div
                  style={{
                    background: "var(--bg-surface)",
                    borderRadius: "10px",
                    border: "1px solid var(--border-subtle)",
                    padding: "16px",
                    display: "flex",
                    flexDirection: "column",
                    justifyContent: "space-between",
                  }}
                >
                  <div>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                      <span style={{ fontSize: "12px", fontWeight: "800", color: "var(--accent-cyan)", display: "flex", alignItems: "center", gap: "6px" }}>
                        ⚡ E8 · Operations Telemetry
                      </span>
                      <span style={{ fontSize: "10px", fontWeight: "700", padding: "2px 6px", borderRadius: "4px", background: "rgba(34,197,94,0.15)", color: "#22c55e" }}>
                        ACTIVE
                      </span>
                    </div>
                    <div style={{ fontSize: "11px", color: "var(--text-muted)", marginBottom: "12px" }}>
                      Live throughput, latency percentiles, HMAC audit logs, and adaptive circuit breakers.
                    </div>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px", marginBottom: "12px" }}>
                      <div style={{ background: "var(--bg-surface-elevated)", padding: "8px", borderRadius: "6px" }}>
                        <div style={{ fontSize: "10px", color: "var(--text-dim)" }}>Throughput / Latency</div>
                        <div style={{ fontSize: "12px", fontWeight: "800", color: "var(--text-main)" }}>
                          {socOverviewData?.capabilities?.e8_operations_telemetry?.requests_per_sec?.toFixed(1) ?? "0.0"} rps | {socOverviewData?.capabilities?.e8_operations_telemetry?.p95_latency_ms?.toFixed(0) ?? "0"}ms
                        </div>
                      </div>
                      <div style={{ background: "var(--bg-surface-elevated)", padding: "8px", borderRadius: "6px" }}>
                        <div style={{ fontSize: "10px", color: "var(--text-dim)" }}>Circuit State</div>
                        <div style={{ fontSize: "12px", fontWeight: "800", color: "#22c55e" }}>
                          {socOverviewData?.capabilities?.e8_operations_telemetry?.circuit_breaker_status || "CLOSED (Active)"}
                        </div>
                      </div>
                    </div>
                  </div>
                  <button
                    onClick={() => navigateToSocView("operations")}
                    style={{
                      width: "100%",
                      padding: "8px",
                      borderRadius: "6px",
                      background: "rgba(99,102,241,0.15)",
                      color: "var(--accent-primary)",
                      border: "1px solid rgba(99,102,241,0.3)",
                      fontSize: "11px",
                      fontWeight: "700",
                      cursor: "pointer",
                      textAlign: "center",
                    }}
                  >
                    View Operations Dashboard →
                  </button>
                </div>

                {/* Card 9: Claude Code Configuration Audit */}
                <div
                  id="soc-claude-code-card"
                  data-testid="soc-claude-code-card"
                  style={{
                    background: "var(--bg-surface)",
                    borderRadius: "10px",
                    border: activeTab === "claude_code" ? "1px solid #c084fc" : "1px solid var(--border-subtle)",
                    padding: "16px",
                    display: "flex",
                    flexDirection: "column",
                    justifyContent: "space-between",
                    position: "relative",
                    zIndex: 1,
                    pointerEvents: "auto",
                  }}
                >
                  <div>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                      <span style={{ fontSize: "12px", fontWeight: "800", color: "#c084fc", display: "flex", alignItems: "center", gap: "6px" }}>
                        🛡️ Claude Code Config Audit
                      </span>
                      <span style={{ fontSize: "10px", fontWeight: "700", padding: "2px 6px", borderRadius: "4px", background: "rgba(168, 85, 247, 0.15)", color: "#c084fc" }}>
                        ASI06 · LLM08 · ASI02
                      </span>
                    </div>
                    <div style={{ fontSize: "11px", color: "var(--text-muted)", marginBottom: "12px" }}>
                      Isolated evaluation of CLAUDE.md, settings.json, permissions, and agent boundaries with dynamic hook testing.
                    </div>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px", marginBottom: "12px" }}>
                      <div style={{ background: "var(--bg-surface-elevated)", padding: "8px", borderRadius: "6px" }}>
                        <div style={{ fontSize: "10px", color: "var(--text-dim)" }}>Files Evaluated</div>
                        <div style={{ fontSize: "16px", fontWeight: "800", color: "#f8fafc" }}>
                          4 Specs
                        </div>
                      </div>
                      <div style={{ background: "var(--bg-surface-elevated)", padding: "8px", borderRadius: "6px" }}>
                        <div style={{ fontSize: "10px", color: "var(--text-dim)" }}>Containment</div>
                        <div style={{ fontSize: "16px", fontWeight: "800", color: "#22c55e" }}>
                          SANDBOX
                        </div>
                      </div>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => navigateToSocView("claude_code")}
                    style={{
                      width: "100%",
                      padding: "8px",
                      borderRadius: "6px",
                      background: "rgba(168, 85, 247, 0.15)",
                      color: "#c084fc",
                      border: "1px solid rgba(168, 85, 247, 0.3)",
                      fontSize: "11px",
                      fontWeight: "700",
                      cursor: "pointer",
                      textAlign: "center",
                      pointerEvents: "auto",
                    }}
                  >
                    Launch Claude Code Audit →
                  </button>
                </div>
              </div>

              {/* Shared Cross-Module Context & Drill-Down Hub */}
              <div
                style={{
                  background: "var(--bg-surface)",
                  borderRadius: "10px",
                  border: "1px solid var(--border-subtle)",
                  padding: "16px",
                }}
              >
                <div style={{ fontSize: "13px", fontWeight: "700", color: "var(--text-main)", marginBottom: "8px" }}>
                  🔗 Cross-Module Context & Drill-Down Matrix
                </div>
                <div style={{ fontSize: "12px", color: "var(--text-muted)", marginBottom: "12px" }}>
                  Use contextual drill-downs to trace a finding from its wire evidence to decision explainability, regression comparisons, and enterprise audit reports.
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: "10px" }}>
                  <button
                    onClick={() => navigateToSocView("lifecycle")}
                    style={{
                      padding: "8px 14px",
                      borderRadius: "6px",
                      background: "var(--bg-surface-elevated)",
                      border: "1px solid var(--border-subtle)",
                      color: "var(--text-main)",
                      fontSize: "12px",
                      cursor: "pointer",
                    }}
                  >
                    📋 View Findings in Lifecycle
                  </button>
                  <button
                    onClick={() => navigateToSocView("explainability")}
                    style={{
                      padding: "8px 14px",
                      borderRadius: "6px",
                      background: "var(--bg-surface-elevated)",
                      border: "1px solid var(--border-subtle)",
                      color: "var(--text-main)",
                      fontSize: "12px",
                      cursor: "pointer",
                    }}
                  >
                    ⚖️ Inspect Explainable Decisions
                  </button>
                  <button
                    onClick={() => navigateToSocView("enterprise_reporting")}
                    style={{
                      padding: "8px 14px",
                      borderRadius: "6px",
                      background: "var(--bg-surface-elevated)",
                      border: "1px solid var(--border-subtle)",
                      color: "var(--text-main)",
                      fontSize: "12px",
                      cursor: "pointer",
                    }}
                  >
                    📑 Generate Enterprise Report
                  </button>
                  <button
                    onClick={() => navigateToSocView("operations")}
                    style={{
                      padding: "8px 14px",
                      borderRadius: "6px",
                      background: "var(--bg-surface-elevated)",
                      border: "1px solid var(--border-subtle)",
                      color: "var(--text-main)",
                      fontSize: "12px",
                      cursor: "pointer",
                    }}
                  >
                    ⚡ Monitor Operations & Telemetry
                  </button>
                  <button
                    type="button"
                    onClick={() => navigateToSocView("claude_code")}
                    style={{
                      padding: "8px 14px",
                      borderRadius: "6px",
                      background: "rgba(168, 85, 247, 0.15)",
                      border: "1px solid rgba(168, 85, 247, 0.3)",
                      color: "#c084fc",
                      fontSize: "12px",
                      fontWeight: "700",
                      cursor: "pointer",
                      pointerEvents: "auto",
                    }}
                  >
                    🛡️ Claude Code Audit
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* TAB E1: Dynamic Security Intelligence */}
          {activeTab === "intelligence" && (
            <div>
              {/* Header and Controls */}
              <div style={{ background: "var(--bg-surface)", borderRadius: "10px", border: "1px solid var(--border-subtle)", padding: "16px", marginBottom: "16px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
                  <div>
                    <h3 style={{ fontSize: "15px", fontWeight: "800", color: "var(--text-main)", margin: "0 0 4px 0" }}>
                      🧠 Phase E1 · Dynamic Threat Profiling & Risk Prioritization
                    </h3>
                    <div style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                      Live autonomous prioritization based on application context, historical triggers, and architectural footprint.
                    </div>
                  </div>
                  <button
                    onClick={handleFetchIntelligence}
                    disabled={intelligenceLoading}
                    style={{
                      padding: "8px 14px",
                      background: "var(--accent-primary)",
                      color: "#fff",
                      border: "none",
                      borderRadius: "6px",
                      fontSize: "12px",
                      fontWeight: "700",
                      cursor: intelligenceLoading ? "not-allowed" : "pointer",
                    }}
                  >
                    {intelligenceLoading ? "Updating..." : "🔄 Refresh Intelligence"}
                  </button>
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "10px" }}>
                  <div>
                    <label style={{ display: "block", fontSize: "11px", color: "var(--text-dim)", marginBottom: "3px" }}>Application ID</label>
                    <input
                      type="text"
                      value={intelAppId}
                      onChange={(e) => setIntelAppId(e.target.value)}
                      style={{ width: "100%", padding: "6px 10px", borderRadius: "4px", background: "var(--bg-primary)", border: "1px solid var(--border-subtle)", color: "var(--text-main)", fontSize: "12px" }}
                    />
                  </div>
                  <div>
                    <label style={{ display: "block", fontSize: "11px", color: "var(--text-dim)", marginBottom: "3px" }}>Version</label>
                    <input
                      type="text"
                      value={intelVersion}
                      onChange={(e) => setIntelVersion(e.target.value)}
                      style={{ width: "100%", padding: "6px 10px", borderRadius: "4px", background: "var(--bg-primary)", border: "1px solid var(--border-subtle)", color: "var(--text-main)", fontSize: "12px" }}
                    />
                  </div>
                  <div>
                    <label style={{ display: "block", fontSize: "11px", color: "var(--text-dim)", marginBottom: "3px" }}>Environment</label>
                    <input
                      type="text"
                      value={intelEnv}
                      onChange={(e) => setIntelEnv(e.target.value)}
                      style={{ width: "100%", padding: "6px 10px", borderRadius: "4px", background: "var(--bg-primary)", border: "1px solid var(--border-subtle)", color: "var(--text-main)", fontSize: "12px" }}
                    />
                  </div>
                  <div>
                    <label style={{ display: "block", fontSize: "11px", color: "var(--text-dim)", marginBottom: "3px" }}>Endpoint</label>
                    <input
                      type="text"
                      value={intelEndpoint}
                      onChange={(e) => setIntelEndpoint(e.target.value)}
                      style={{ width: "100%", padding: "6px 10px", borderRadius: "4px", background: "var(--bg-primary)", border: "1px solid var(--border-subtle)", color: "var(--text-main)", fontSize: "12px" }}
                    />
                  </div>
                </div>
              </div>

              {/* Dynamic Priorities Table */}
              <div style={{ background: "var(--bg-surface)", borderRadius: "10px", border: "1px solid var(--border-subtle)", padding: "16px", marginBottom: "16px" }}>
                <h4 style={{ fontSize: "13px", fontWeight: "700", color: "var(--text-main)", marginBottom: "10px" }}>
                  Ranked Risk Priorities ({intelligencePriorities.length > 0 ? intelligencePriorities.length : risksList.length} Risks)
                </h4>
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px" }}>
                    <thead>
                      <tr style={{ borderBottom: "1px solid var(--border-subtle)", color: "var(--text-dim)", textAlign: "left" }}>
                        <th style={{ padding: "8px 10px" }}>Risk ID</th>
                        <th style={{ padding: "8px 10px" }}>Risk Name</th>
                        <th style={{ padding: "8px 10px" }}>Category</th>
                        <th style={{ padding: "8px 10px" }}>Priority</th>
                        <th style={{ padding: "8px 10px" }}>Weight / Score</th>
                        <th style={{ padding: "8px 10px" }}>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(intelligencePriorities.length > 0 ? intelligencePriorities : risksList).map((r, idx) => {
                        const prio = r.priority || (idx < 5 ? "HIGH" : idx < 12 ? "MEDIUM" : "LOW");
                        const prioColor = prio === "HIGH" ? "#ef4444" : prio === "MEDIUM" ? "#eab308" : "#22c55e";
                        return (
                          <tr key={idx} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                            <td style={{ padding: "8px 10px", fontFamily: "DM Mono, monospace", fontWeight: "700", color: "var(--accent-cyan)" }}>
                              {r.risk_id}
                            </td>
                            <td style={{ padding: "8px 10px", color: "var(--text-main)" }}>
                              {r.risk_name}
                            </td>
                            <td style={{ padding: "8px 10px", color: "var(--text-muted)" }}>
                              {r.category || (r.risk_id.startsWith("LLM") ? "OWASP Top 10 for LLM" : "OWASP Agentic Security")}
                            </td>
                            <td style={{ padding: "8px 10px" }}>
                              <span style={{ padding: "2px 6px", borderRadius: "4px", fontSize: "10px", fontWeight: "700", background: `${prioColor}22`, color: prioColor }}>
                                {prio}
                              </span>
                            </td>
                            <td style={{ padding: "8px 10px", color: "var(--text-muted)" }}>
                              {r.score ? r.score.toFixed(2) : (1.0 - idx * 0.04).toFixed(2)}
                            </td>
                            <td style={{ padding: "8px 10px" }}>
                              <button
                                onClick={() => {
                                  if (!selectedRisks.includes(r.risk_id)) {
                                    setSelectedRisks([...selectedRisks, r.risk_id]);
                                  }
                                  setCommand(`Audit application for ${r.risk_id} against ${targetUrl}`);
                                }}
                                style={{
                                  padding: "3px 8px",
                                  borderRadius: "4px",
                                  background: "rgba(99,102,241,0.2)",
                                  color: "var(--accent-primary)",
                                  border: "1px solid rgba(99,102,241,0.3)",
                                  fontSize: "10px",
                                  fontWeight: "600",
                                  cursor: "pointer",
                                }}
                              >
                                Select for Audit
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* TAB E2: Advanced Attack Graph Planning */}
          {activeTab === "attack_graph" && (
            <div>
              {/* Header and Controls */}
              <div style={{ background: "var(--bg-surface)", borderRadius: "10px", border: "1px solid var(--border-subtle)", padding: "16px", marginBottom: "16px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
                  <div>
                    <h3 style={{ fontSize: "15px", fontWeight: "800", color: "var(--text-main)", margin: "0 0 4px 0" }}>
                      🕸️ Phase E2 · Multi-Stage Attack Graph & Exploit Path Planning
                    </h3>
                    <div style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                      Tarjan SCC cycle analysis, candidate exploit path synthesis, and traversal probability modeling.
                    </div>
                  </div>
                  <div style={{ display: "flex", gap: "8px" }}>
                    <button
                      onClick={handleFetchAttackGraph}
                      disabled={isAnalyzingGraph}
                      style={{
                        padding: "8px 14px",
                        background: "var(--bg-surface-elevated)",
                        color: "var(--text-main)",
                        border: "1px solid var(--border-subtle)",
                        borderRadius: "6px",
                        fontSize: "12px",
                        fontWeight: "600",
                        cursor: isAnalyzingGraph ? "not-allowed" : "pointer",
                      }}
                    >
                      {isAnalyzingGraph ? "Analyzing..." : "🔄 Refresh Graph"}
                    </button>
                    <button
                      onClick={handleGenerateCandidatePaths}
                      disabled={isGeneratingPaths}
                      style={{
                        padding: "8px 14px",
                        background: "var(--accent-primary)",
                        color: "#fff",
                        border: "none",
                        borderRadius: "6px",
                        fontSize: "12px",
                        fontWeight: "700",
                        cursor: isGeneratingPaths ? "not-allowed" : "pointer",
                      }}
                    >
                      {isGeneratingPaths ? "Generating..." : "⚡ Generate Exploit Paths"}
                    </button>
                  </div>
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "10px" }}>
                  <div>
                    <label style={{ display: "block", fontSize: "11px", color: "var(--text-dim)", marginBottom: "3px" }}>Application ID</label>
                    <input
                      type="text"
                      value={graphAppId}
                      onChange={(e) => setGraphAppId(e.target.value)}
                      style={{ width: "100%", padding: "6px 10px", borderRadius: "4px", background: "var(--bg-primary)", border: "1px solid var(--border-subtle)", color: "var(--text-main)", fontSize: "12px" }}
                    />
                  </div>
                  <div>
                    <label style={{ display: "block", fontSize: "11px", color: "var(--text-dim)", marginBottom: "3px" }}>Environment</label>
                    <input
                      type="text"
                      value={graphEnv}
                      onChange={(e) => setGraphEnv(e.target.value)}
                      style={{ width: "100%", padding: "6px 10px", borderRadius: "4px", background: "var(--bg-primary)", border: "1px solid var(--border-subtle)", color: "var(--text-main)", fontSize: "12px" }}
                    />
                  </div>
                  <div>
                    <label style={{ display: "block", fontSize: "11px", color: "var(--text-dim)", marginBottom: "3px" }}>Endpoint</label>
                    <input
                      type="text"
                      value={graphEndpoint}
                      onChange={(e) => setGraphEndpoint(e.target.value)}
                      style={{ width: "100%", padding: "6px 10px", borderRadius: "4px", background: "var(--bg-primary)", border: "1px solid var(--border-subtle)", color: "var(--text-main)", fontSize: "12px" }}
                    />
                  </div>
                </div>
              </div>

              {/* Attack Paths and Components */}
              <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: "16px" }}>
                <div style={{ background: "var(--bg-surface)", borderRadius: "10px", border: "1px solid var(--border-subtle)", padding: "16px" }}>
                  <h4 style={{ fontSize: "13px", fontWeight: "700", color: "var(--text-main)", marginBottom: "12px" }}>
                    Candidate Exploit Paths ({candidatePathsData?.paths?.length || 0})
                  </h4>
                  {candidatePathsData?.paths?.length > 0 ? (
                    <div style={{ display: "flex", flexDirection: "column", gap: "8px", maxHeight: "360px", overflowY: "auto" }}>
                      {candidatePathsData.paths.map((p, idx) => (
                        <div
                          key={idx}
                          onClick={() => setSelectedPathId(p.path_id)}
                          style={{
                            padding: "10px",
                            borderRadius: "6px",
                            background: selectedPathId === p.path_id ? "rgba(99,102,241,0.15)" : "var(--bg-surface-elevated)",
                            border: `1px solid ${selectedPathId === p.path_id ? "var(--accent-primary)" : "var(--border-subtle)"}`,
                            cursor: "pointer",
                          }}
                        >
                          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "4px" }}>
                            <span style={{ fontSize: "11px", fontWeight: "700", color: "var(--accent-cyan)", fontFamily: "DM Mono, monospace" }}>
                              {p.path_id}
                            </span>
                            <span style={{ fontSize: "10px", color: "var(--text-dim)" }}>
                              Prob: {((p.exploit_probability || 0.8) * 100).toFixed(0)}%
                            </span>
                          </div>
                          <div style={{ fontSize: "12px", color: "var(--text-main)", marginBottom: "4px" }}>
                            {p.steps?.map((s) => s.risk_id || s).join(" ➔ ") || "Multi-stage chain"}
                          </div>
                          <div style={{ fontSize: "10px", color: "var(--text-muted)" }}>
                            Length: {p.steps?.length || p.length || 3} steps | Target: {p.target_endpoint || "/api/chat"}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div style={{ padding: "30px", textAlign: "center", color: "var(--text-dim)", fontSize: "12px" }}>
                      Click "Generate Exploit Paths" to synthesize graph traversal chains.
                    </div>
                  )}
                </div>

                <div style={{ background: "var(--bg-surface)", borderRadius: "10px", border: "1px solid var(--border-subtle)", padding: "16px" }}>
                  <h4 style={{ fontSize: "13px", fontWeight: "700", color: "var(--text-main)", marginBottom: "12px" }}>
                    Tarjan Strongly Connected Components (SCCs)
                  </h4>
                  {attackGraphData?.sccs?.length > 0 ? (
                    <div style={{ display: "flex", flexDirection: "column", gap: "8px", maxHeight: "360px", overflowY: "auto" }}>
                      {attackGraphData.sccs.map((scc, idx) => (
                        <div key={idx} style={{ padding: "10px", borderRadius: "6px", background: "var(--bg-surface-elevated)", border: "1px solid var(--border-subtle)" }}>
                          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "4px" }}>
                            <span style={{ fontSize: "11px", fontWeight: "700", color: "var(--text-main)" }}>
                              SCC #{idx + 1} ({scc.nodes?.length || 0} Nodes)
                            </span>
                            <span style={{ fontSize: "10px", fontWeight: "700", color: scc.is_cyclic ? "#eab308" : "#22c55e" }}>
                              {scc.is_cyclic ? "CYCLIC LOOP" : "ACYCLIC"}
                            </span>
                          </div>
                          <div style={{ fontSize: "11px", color: "var(--text-muted)", fontFamily: "DM Mono, monospace" }}>
                            {scc.nodes?.join(", ")}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div style={{ padding: "30px", textAlign: "center", color: "var(--text-dim)", fontSize: "12px" }}>
                      {isAnalyzingGraph ? "Analyzing graph topology..." : "Graph analysis loaded. 0 cyclic loops detected."}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* TAB E3: Deep OpenAPI Schema Intelligence */}
          {activeTab === "schema_intelligence" && (
            <div>
              {/* Header and Controls */}
              <div style={{ background: "var(--bg-surface)", borderRadius: "10px", border: "1px solid var(--border-subtle)", padding: "16px", marginBottom: "16px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
                  <div>
                    <h3 style={{ fontSize: "15px", fontWeight: "800", color: "var(--text-main)", margin: "0 0 4px 0" }}>
                      📜 Phase E3 · Deep OpenAPI Schema Intelligence
                    </h3>
                    <div style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                      Automated endpoint discovery, boundary mutation payloads, and schema-guided test plans.
                    </div>
                  </div>
                  <div style={{ display: "flex", gap: "8px" }}>
                    <button
                      onClick={handleFetchLiveSchema}
                      disabled={isAnalyzingSchema}
                      style={{
                        padding: "8px 14px",
                        background: "var(--bg-surface-elevated)",
                        color: "var(--text-main)",
                        border: "1px solid var(--border-subtle)",
                        borderRadius: "6px",
                        fontSize: "12px",
                        fontWeight: "600",
                        cursor: isAnalyzingSchema ? "not-allowed" : "pointer",
                      }}
                    >
                      {isAnalyzingSchema ? "Analyzing..." : "🔍 Inspect Live Spec"}
                    </button>
                    <button
                      onClick={() => setCustomSpecModal(true)}
                      style={{
                        padding: "8px 14px",
                        background: "var(--bg-surface-elevated)",
                        color: "var(--accent-cyan)",
                        border: "1px solid var(--border-subtle)",
                        borderRadius: "6px",
                        fontSize: "12px",
                        fontWeight: "600",
                        cursor: "pointer",
                      }}
                    >
                      📝 Paste Custom Spec
                    </button>
                    <button
                      onClick={handleGenerateSchemaTestPlans}
                      disabled={isGeneratingSchemaTests}
                      style={{
                        padding: "8px 14px",
                        background: "var(--accent-primary)",
                        color: "#fff",
                        border: "none",
                        borderRadius: "6px",
                        fontSize: "12px",
                        fontWeight: "700",
                        cursor: isGeneratingSchemaTests ? "not-allowed" : "pointer",
                      }}
                    >
                      {isGeneratingSchemaTests ? "Generating..." : "⚡ Generate Schema Tests"}
                    </button>
                  </div>
                </div>

                <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
                  <span style={{ fontSize: "12px", color: "var(--text-dim)" }}>Target Base URL:</span>
                  <span style={{ fontSize: "12px", fontFamily: "DM Mono, monospace", color: "var(--accent-cyan)" }}>
                    {targetUrl || "http://127.0.0.1:8000"}
                  </span>
                </div>
              </div>

              {/* Endpoints Table */}
              <div style={{ background: "var(--bg-surface)", borderRadius: "10px", border: "1px solid var(--border-subtle)", padding: "16px", marginBottom: "16px" }}>
                <h4 style={{ fontSize: "13px", fontWeight: "700", color: "var(--text-main)", marginBottom: "10px" }}>
                  Analyzed Endpoints ({schemaAnalysisData?.endpoints?.length || 0})
                </h4>
                {schemaAnalysisData?.endpoints?.length > 0 ? (
                  <div style={{ overflowX: "auto" }}>
                    <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px" }}>
                      <thead>
                        <tr style={{ borderBottom: "1px solid var(--border-subtle)", color: "var(--text-dim)", textAlign: "left" }}>
                          <th style={{ padding: "8px 10px" }}>Method</th>
                          <th style={{ padding: "8px 10px" }}>Path</th>
                          <th style={{ padding: "8px 10px" }}>Parameters</th>
                          <th style={{ padding: "8px 10px" }}>Auth Requirement</th>
                          <th style={{ padding: "8px 10px" }}>Risk Surface</th>
                        </tr>
                      </thead>
                      <tbody>
                        {schemaAnalysisData.endpoints.map((ep, idx) => (
                          <tr key={idx} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                            <td style={{ padding: "8px 10px" }}>
                              <span style={{ padding: "2px 6px", borderRadius: "4px", fontSize: "10px", fontWeight: "800", background: ep.method === "POST" ? "rgba(99,102,241,0.2)" : "rgba(34,197,94,0.2)", color: ep.method === "POST" ? "var(--accent-primary)" : "#22c55e" }}>
                                {ep.method || "POST"}
                              </span>
                            </td>
                            <td style={{ padding: "8px 10px", fontFamily: "DM Mono, monospace", color: "var(--text-main)" }}>
                              {ep.endpoint || ep.path}
                            </td>
                            <td style={{ padding: "8px 10px", color: "var(--text-muted)" }}>
                              {ep.parameters?.length || 0} params
                            </td>
                            <td style={{ padding: "8px 10px", color: "var(--text-muted)" }}>
                              {ep.auth_required ? "Bearer Auth" : "None / Public"}
                            </td>
                            <td style={{ padding: "8px 10px", color: "var(--accent-cyan)" }}>
                              {ep.inferred_risks?.join(", ") || "LLM01, ASI01"}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div style={{ padding: "30px", textAlign: "center", color: "var(--text-dim)", fontSize: "12px" }}>
                    Click "Inspect Live Spec" to extract endpoints from target application OpenAPI definition.
                  </div>
                )}
              </div>

              {/* Custom Spec Modal */}
              {customSpecModal && (
                <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)", display: "flex", justifyContent: "center", alignItems: "center", zIndex: 1000 }}>
                  <div style={{ background: "var(--bg-surface)", border: "1px solid var(--border-subtle)", borderRadius: "12px", padding: "20px", width: "90%", maxWidth: "600px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
                      <h3 style={{ fontSize: "15px", fontWeight: "700", color: "var(--text-main)", margin: 0 }}>
                        Paste OpenAPI / Swagger JSON Specification
                      </h3>
                      <button onClick={() => setCustomSpecModal(false)} style={{ background: "transparent", border: "none", color: "var(--text-dim)", cursor: "pointer", fontSize: "14px" }}>
                        ✕
                      </button>
                    </div>
                    <textarea
                      rows={10}
                      value={customSpecText}
                      onChange={(e) => setCustomSpecText(e.target.value)}
                      placeholder='{"openapi": "3.0.0", "paths": {...}}'
                      style={{ width: "100%", padding: "10px", borderRadius: "6px", background: "var(--bg-primary)", border: "1px solid var(--border-subtle)", color: "var(--text-main)", fontFamily: "DM Mono, monospace", fontSize: "12px", marginBottom: "12px" }}
                    />
                    <div style={{ display: "flex", justifyContent: "flex-end", gap: "8px" }}>
                      <button onClick={() => setCustomSpecModal(false)} style={{ padding: "8px 14px", borderRadius: "6px", background: "transparent", border: "1px solid var(--border-subtle)", color: "var(--text-muted)", cursor: "pointer" }}>
                        Cancel
                      </button>
                      <button onClick={handleAnalyzeCustomSchema} style={{ padding: "8px 14px", borderRadius: "6px", background: "var(--accent-primary)", border: "none", color: "#fff", fontWeight: "700", cursor: "pointer" }}>
                        Analyze Specification
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB E4: Vulnerability & Evidence Lifecycle */}
          {activeTab === "lifecycle" && (
            <div>
              {/* Header and Controls */}
              <div style={{ background: "var(--bg-surface)", borderRadius: "10px", border: "1px solid var(--border-subtle)", padding: "16px", marginBottom: "16px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <div>
                    <h3 style={{ fontSize: "15px", fontWeight: "800", color: "var(--text-main)", margin: "0 0 4px 0" }}>
                      📋 Phase E4 · Vulnerability & Cryptographic Evidence Lifecycle
                    </h3>
                    <div style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                      Kanban governance across 7 strict states with mandatory justifications and evidence references.
                    </div>
                  </div>
                  <button
                    onClick={handleFetchLifecycleBoard}
                    disabled={isFetchingLifecycle}
                    style={{
                      padding: "8px 14px",
                      background: "var(--accent-primary)",
                      color: "#fff",
                      border: "none",
                      borderRadius: "6px",
                      fontSize: "12px",
                      fontWeight: "700",
                      cursor: isFetchingLifecycle ? "not-allowed" : "pointer",
                    }}
                  >
                    {isFetchingLifecycle ? "Refreshing..." : "🔄 Refresh Kanban Board"}
                  </button>
                </div>
              </div>

              {/* Kanban Columns (11 Canonical Lifecycle States) */}
              <div
                style={{
                  display: "flex",
                  gap: "10px",
                  marginBottom: "16px",
                  overflowX: "auto",
                  paddingBottom: "10px",
                }}
              >
                {[
                  { key: "DETECTED", label: "Detected", color: "#64748b" },
                  { key: "TRIAGE", label: "Triage", color: "#71717a" },
                  { key: "POTENTIAL", label: "Potential", color: "#f59e0b" },
                  { key: "CONFIRMED", label: "Confirmed", color: "#ef4444" },
                  { key: "REMEDIATION_PLANNED", label: "Remediation Planned", color: "#3b82f6" },
                  { key: "REMEDIATION_IN_PROGRESS", label: "In Progress", color: "#6366f1" },
                  { key: "READY_FOR_RETEST", label: "Ready Retest", color: "#8b5cf6" },
                  { key: "REMEDIATION_VERIFIED", label: "Verified", color: "#10b981" },
                  { key: "REFUTED", label: "Refuted", color: "#94a3b8" },
                  { key: "INCONCLUSIVE", label: "Inconclusive", color: "#a1a1aa" },
                  { key: "CLOSED", label: "Closed", color: "#14b8a6" },
                ].map((col) => {
                  const colData = lifecycleBoard?.columns?.[col.key];
                  const findingsInCol = Array.isArray(colData) ? colData : (colData?.findings || []);
                  const count = colData?.count ?? findingsInCol.length;
                  return (
                    <div
                      key={col.key}
                      style={{
                        background: "var(--bg-surface)",
                        borderRadius: "8px",
                        border: "1px solid var(--border-subtle)",
                        padding: "12px",
                        minWidth: "190px",
                        maxWidth: "220px",
                        flex: "0 0 200px",
                        minHeight: "340px",
                        display: "flex",
                        flexDirection: "column",
                      }}
                    >
                      <div
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          alignItems: "center",
                          marginBottom: "10px",
                          paddingBottom: "6px",
                          borderBottom: `2px solid ${col.color}`,
                        }}
                      >
                        <span style={{ fontSize: "11px", fontWeight: "700", color: "var(--text-main)" }}>
                          {col.label}
                        </span>
                        <span
                          style={{
                            fontSize: "10px",
                            fontWeight: "800",
                            padding: "1px 6px",
                            borderRadius: "8px",
                            background: `${col.color}22`,
                            color: col.color,
                          }}
                        >
                          {count}
                        </span>
                      </div>
                      <div
                        style={{
                          display: "flex",
                          flexDirection: "column",
                          gap: "8px",
                          flex: 1,
                          overflowY: "auto",
                          maxHeight: "400px",
                        }}
                      >
                        {findingsInCol.length === 0 && (
                          <div
                            style={{
                              fontSize: "10px",
                              color: "var(--text-dim)",
                              textAlign: "center",
                              marginTop: "20px",
                              fontStyle: "italic",
                            }}
                          >
                            No findings
                          </div>
                        )}
                        {findingsInCol.map((f, fIdx) => (
                          <div
                            key={fIdx}
                            onClick={() => handleSelectLifecycleFinding(f.finding_id)}
                            style={{
                              padding: "10px",
                              borderRadius: "6px",
                              background:
                                selectedLifecycleFinding?.finding_id === f.finding_id
                                  ? "rgba(99,102,241,0.2)"
                                  : "var(--bg-surface-elevated)",
                              border: `1px solid ${
                                selectedLifecycleFinding?.finding_id === f.finding_id
                                  ? "var(--accent-primary)"
                                  : "var(--border-subtle)"
                              }`,
                              cursor: "pointer",
                            }}
                          >
                            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "4px" }}>
                              <span
                                style={{
                                  fontSize: "10px",
                                  fontWeight: "700",
                                  color: "var(--accent-cyan)",
                                  fontFamily: "DM Mono, monospace",
                                }}
                              >
                                {f.finding_id}
                              </span>
                              <span
                                style={{
                                  fontSize: "9px",
                                  fontWeight: "700",
                                  padding: "1px 4px",
                                  borderRadius: "3px",
                                  background:
                                    f.severity === "CRITICAL"
                                      ? "rgba(239,68,68,0.2)"
                                      : f.severity === "HIGH"
                                      ? "rgba(249,115,22,0.2)"
                                      : "rgba(234,179,8,0.2)",
                                  color:
                                    f.severity === "CRITICAL"
                                      ? "#ef4444"
                                      : f.severity === "HIGH"
                                      ? "#f97316"
                                      : "#eab308",
                                }}
                              >
                                {f.severity}
                              </span>
                            </div>
                            <div
                              style={{
                                fontSize: "11px",
                                fontWeight: "600",
                                color: "var(--text-main)",
                                marginBottom: "4px",
                                overflow: "hidden",
                                textOverflow: "ellipsis",
                                whiteSpace: "nowrap",
                              }}
                            >
                              {f.title || f.risk_code}
                            </div>
                            <div style={{ fontSize: "9px", color: "var(--text-dim)" }}>
                              CVSS: {f.cvss_score || "N/A"} | Risk: {f.risk_code}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Selected Finding Detail & Transition Controller */}
              {selectedLifecycleFinding && (
                <div
                  style={{
                    background: "var(--bg-surface)",
                    borderRadius: "10px",
                    border: "1px solid var(--accent-primary)",
                    padding: "16px",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "flex-start",
                      marginBottom: "12px",
                    }}
                  >
                    <div>
                      <h4 style={{ fontSize: "14px", fontWeight: "800", color: "var(--text-main)", margin: "0 0 4px 0" }}>
                        Finding Details: {selectedLifecycleFinding.finding_id}
                      </h4>
                      <div style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                        {selectedLifecycleFinding.title} · State: <strong>{selectedLifecycleFinding.lifecycle_status}</strong>
                      </div>
                    </div>
                    {/* Drill-Down Shortcuts */}
                    <div style={{ display: "flex", gap: "8px" }}>
                      <button
                        onClick={() => navigateToSocView("explainability", { findingId: selectedLifecycleFinding.finding_id })}
                        style={{
                          padding: "6px 10px",
                          borderRadius: "4px",
                          background: "rgba(99,102,241,0.2)",
                          color: "var(--accent-cyan)",
                          border: "1px solid rgba(99,102,241,0.4)",
                          fontSize: "11px",
                          fontWeight: "600",
                          cursor: "pointer",
                        }}
                      >
                        ⚖️ E7 Decisions
                      </button>
                      <button
                        onClick={() => navigateToSocView("enterprise_reporting", { planId: selectedLifecycleFinding.execution_id })}
                        style={{
                          padding: "6px 10px",
                          borderRadius: "4px",
                          background: "rgba(99,102,241,0.2)",
                          color: "var(--accent-cyan)",
                          border: "1px solid rgba(99,102,241,0.4)",
                          fontSize: "11px",
                          fontWeight: "600",
                          cursor: "pointer",
                        }}
                      >
                        📑 E6 Report
                      </button>
                    </div>
                  </div>

                  {/* Transition Form */}
                  <div
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      gap: "10px",
                      background: "var(--bg-surface-elevated)",
                      padding: "14px",
                      borderRadius: "8px",
                    }}
                  >
                    <div
                      style={{
                        display: "grid",
                        gridTemplateColumns: "1.2fr 2fr 1.5fr auto",
                        gap: "10px",
                        alignItems: "flex-end",
                      }}
                    >
                      <div>
                        <label
                          style={{
                            display: "block",
                            fontSize: "11px",
                            fontWeight: "600",
                            color: "var(--text-dim)",
                            marginBottom: "4px",
                          }}
                        >
                          Target State *
                        </label>
                        <select
                          id="lifecycle-target-state-select"
                          value={lifecycleTransitionTarget}
                          onChange={(e) => setLifecycleTransitionTarget(e.target.value)}
                          style={{
                            width: "100%",
                            padding: "6px 8px",
                            borderRadius: "4px",
                            background: "var(--bg-primary)",
                            border: "1px solid var(--border-subtle)",
                            color: "var(--text-main)",
                            fontSize: "11px",
                          }}
                        >
                          <option value="">Select canonical target state...</option>
                          <option value="DETECTED">DETECTED</option>
                          <option value="TRIAGE">TRIAGE</option>
                          <option value="POTENTIAL">POTENTIAL</option>
                          <option value="CONFIRMED">CONFIRMED</option>
                          <option value="REMEDIATION_PLANNED">REMEDIATION_PLANNED</option>
                          <option value="REMEDIATION_IN_PROGRESS">REMEDIATION_IN_PROGRESS</option>
                          <option value="READY_FOR_RETEST">READY_FOR_RETEST</option>
                          <option value="REMEDIATION_VERIFIED">REMEDIATION_VERIFIED</option>
                          <option value="REFUTED">REFUTED</option>
                          <option value="INCONCLUSIVE">INCONCLUSIVE</option>
                          <option value="CLOSED">CLOSED</option>
                        </select>
                      </div>
                      <div>
                        <label
                          style={{
                            display: "block",
                            fontSize: "11px",
                            fontWeight: "600",
                            color: "var(--text-dim)",
                            marginBottom: "4px",
                          }}
                        >
                          Justification Reason *
                        </label>
                        <input
                          id="lifecycle-transition-reason-input"
                          type="text"
                          placeholder="Mandatory justification (min 3 chars)..."
                          value={lifecycleTransitionReason}
                          onChange={(e) => setLifecycleTransitionReason(e.target.value)}
                          style={{
                            width: "100%",
                            padding: "6px 8px",
                            borderRadius: "4px",
                            background: "var(--bg-primary)",
                            border: "1px solid var(--border-subtle)",
                            color: "var(--text-main)",
                            fontSize: "11px",
                          }}
                        />
                      </div>
                      <div>
                        <label
                          style={{
                            display: "block",
                            fontSize: "11px",
                            fontWeight: "600",
                            color: "var(--text-dim)",
                            marginBottom: "4px",
                          }}
                        >
                          Evidence Ref (Optional / Required for CONFIRMED)
                        </label>
                        <input
                          id="lifecycle-transition-evidence-input"
                          type="text"
                          placeholder="sha256:... or evidence ID"
                          value={lifecycleTransitionEvidence}
                          onChange={(e) => setLifecycleTransitionEvidence(e.target.value)}
                          style={{
                            width: "100%",
                            padding: "6px 8px",
                            borderRadius: "4px",
                            background: "var(--bg-primary)",
                            border: "1px solid var(--border-subtle)",
                            color: "var(--text-main)",
                            fontSize: "11px",
                          }}
                        />
                      </div>
                      <div>
                        <button
                          id="lifecycle-execute-transition-btn"
                          onClick={handleExecuteLifecycleTransition}
                          disabled={isExecutingTransition || !lifecycleTransitionTarget}
                          style={{
                            padding: "7px 14px",
                            borderRadius: "4px",
                            background: "var(--accent-primary)",
                            color: "#fff",
                            border: "none",
                            fontSize: "11px",
                            fontWeight: "700",
                            cursor:
                              isExecutingTransition || !lifecycleTransitionTarget
                                ? "not-allowed"
                                : "pointer",
                          }}
                        >
                          {isExecutingTransition ? "Transitioning..." : "Execute Transition"}
                        </button>
                      </div>
                    </div>
                    {/* Secondary Auditor Signoff Checkbox */}
                    <div style={{ display: "flex", alignItems: "center", gap: "8px", marginTop: "2px" }}>
                      <input
                        type="checkbox"
                        id="secondary-auditor-confirm-checkbox"
                        checked={lifecycleIsSecondaryConfirmed}
                        onChange={(e) => setLifecycleIsSecondaryConfirmed(e.target.checked)}
                        style={{ cursor: "pointer" }}
                      />
                      <label
                        htmlFor="secondary-auditor-confirm-checkbox"
                        style={{ fontSize: "11px", color: "var(--text-muted)", cursor: "pointer" }}
                      >
                        Secondary Auditor Signoff (Cryptographic dual-authorization required for CONFIRMED)
                      </label>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 1: Multi-Turn Execution Chains */}
          {activeTab === "chains" && (
            <div>
              {chains.length === 0 ? (
                <div style={{ padding: "40px 20px", textAlign: "center", color: "var(--text-dim)" }}>
                  <div style={{ fontSize: "28px", marginBottom: "8px" }}>🛡️</div>
                  <div style={{ fontSize: "14px", fontWeight: "600", color: "var(--text-muted)" }}>
                    No execution chains generated yet.
                  </div>
                  <div style={{ fontSize: "12px", marginTop: "4px" }}>
                    Enter a natural language command above and click "Execute Adaptive Plan" to begin testing.
                  </div>
                </div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
                  {chains.map((chain) => (
                    <div
                      key={chain.chain_id}
                      style={{
                        background: "var(--bg-surface-elevated)",
                        border: "1px solid var(--border-subtle)",
                        borderRadius: "10px",
                        padding: "16px",
                      }}
                    >
                      {/* Chain Header */}
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                          <span style={{ padding: "2px 8px", borderRadius: "4px", background: "rgba(99,102,241,0.2)", color: "var(--accent-primary)", fontSize: "11px", fontWeight: "700" }}>
                            {chain.risk_id}
                          </span>
                          <strong style={{ fontSize: "14px", color: "var(--text-main)" }}>
                            {chain.scenario_id}: {chain.scenario_name}
                          </strong>
                          <span style={{ fontSize: "11px", color: "var(--text-dim)" }}>
                            ({chain.total_turns} turn{chain.total_turns > 1 ? "s" : ""})
                          </span>
                        </div>

                        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                          <span
                            style={{
                              padding: "3px 10px",
                              borderRadius: "12px",
                              fontSize: "11px",
                              fontWeight: "700",
                              background:
                                chain.final_verdict === "BLOCKED"
                                  ? "rgba(34,197,94,0.15)"
                                  : chain.final_verdict === "VULNERABLE"
                                  ? "rgba(239,68,68,0.15)"
                                  : "rgba(245,158,11,0.15)",
                              color:
                                chain.final_verdict === "BLOCKED"
                                  ? "var(--color-online)"
                                  : chain.final_verdict === "VULNERABLE"
                                  ? "var(--color-error)"
                                  : "var(--color-claude)",
                              border: `1px solid ${
                                chain.final_verdict === "BLOCKED"
                                  ? "rgba(34,197,94,0.3)"
                                  : chain.final_verdict === "VULNERABLE"
                                  ? "rgba(239,68,68,0.3)"
                                  : "rgba(245,158,11,0.3)"
                              }`,
                            }}
                          >
                            {chain.final_verdict}
                          </span>
                        </div>
                      </div>

                      {/* Turns List */}
                      <div style={{ display: "grid", gridTemplateColumns: `repeat(${chain.turns?.length || 1}, 1fr)`, gap: "10px" }}>
                        {chain.turns?.map((turn, tIdx) => (
                          <div
                            key={tIdx}
                            onClick={() => {
                              inspectExecution(turn.execution_id);
                              setActiveTab("evidence");
                            }}
                            style={{
                              background: "var(--bg-primary)",
                              border: `1px solid ${selectedExecutionId === turn.execution_id ? "var(--accent-cyan)" : "var(--border-subtle)"}`,
                              borderRadius: "8px",
                              padding: "10px 12px",
                              cursor: "pointer",
                              transition: "all 0.15s ease",
                            }}
                          >
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
                              <span style={{ fontSize: "11px", fontWeight: "700", color: "var(--text-muted)" }}>
                                TURN {turn.turn_number}
                              </span>
                              <span style={{ fontSize: "10px", fontWeight: "700", color: turn.verdict === "BLOCKED" ? "var(--color-online)" : turn.verdict === "VULNERABLE" ? "var(--color-error)" : "var(--color-claude)" }}>
                                {turn.verdict}
                              </span>
                            </div>
                            <div style={{ fontSize: "11px", color: "var(--text-dim)", marginBottom: "4px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                              Strategy: {turn.mutation_technique || "Base Payload"}
                            </div>
                            <div style={{ fontSize: "10px", color: "var(--text-muted)", fontFamily: "DM Mono, monospace" }}>
                              Latency: {turn.latency_ms?.toFixed(1) || "0.0"}ms · Status: {turn.status_code || "---"}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}



          {/* TAB 2: Payload Mutation Lineage */}
          {activeTab === "mutations" && (
            <div>
              {mutations.length === 0 ? (
                <div style={{ padding: "40px 20px", textAlign: "center", color: "var(--text-dim)" }}>
                  Execute an adaptive test plan to inspect generated payload mutation trees.
                </div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                  {mutations.map((m, idx) => (
                    <div
                      key={idx}
                      style={{
                        background: "var(--bg-surface-elevated)",
                        border: "1px solid var(--border-subtle)",
                        borderRadius: "8px",
                        padding: "12px 14px",
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                          <span style={{ fontSize: "11px", fontFamily: "DM Mono, monospace", color: "var(--accent-primary)", fontWeight: "700" }}>
                            {m.payload_id}
                          </span>
                          <span style={{ fontSize: "11px", padding: "1px 6px", borderRadius: "4px", background: "rgba(99,102,241,0.15)", color: "var(--accent-cyan)" }}>
                            Gen {m.generation} · v{m.version}
                          </span>
                          <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                            Technique: <strong style={{ color: "var(--text-main)" }}>{m.technique}</strong>
                          </span>
                        </div>
                        <span style={{ fontSize: "10px", color: "var(--text-dim)", fontFamily: "DM Mono, monospace" }}>
                          SHA-256: {m.sha256?.slice(0, 12)}...
                        </span>
                      </div>
                      <div style={{ fontSize: "12px", fontFamily: "DM Mono, monospace", background: "var(--bg-primary)", padding: "8px 10px", borderRadius: "6px", color: "var(--text-main)", overflowX: "auto" }}>
                        {m.payload_text}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}



          {/* TAB 3: Wire Evidence & SHA-256 Integrity */}
          {activeTab === "evidence" && (
            <div>
              {!evidenceData ? (
                <div style={{ padding: "40px 20px", textAlign: "center", color: "var(--text-dim)" }}>
                  Select an execution turn from the Multi-Turn Chains tab to view captured HTTP wire evidence.
                </div>
              ) : (
                <div style={{ background: "var(--bg-surface-elevated)", border: "1px solid var(--border-subtle)", borderRadius: "10px", padding: "16px" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "14px" }}>
                    <div>
                      <span style={{ fontSize: "12px", fontWeight: "700", color: "var(--text-muted)" }}>EXECUTION EVIDENCE RECORD</span>
                      <h3 style={{ fontSize: "14px", fontWeight: "700", color: "var(--accent-cyan)", margin: "2px 0 0 0" }}>
                        {evidenceData.execution_id}
                      </h3>
                    </div>
                    <span
                      style={{
                        padding: "3px 10px",
                        borderRadius: "12px",
                        fontSize: "11px",
                        fontWeight: "700",
                        background: evidenceData.verdict === "BLOCKED" ? "rgba(34,197,94,0.15)" : "rgba(239,68,68,0.15)",
                        color: evidenceData.verdict === "BLOCKED" ? "var(--color-online)" : "var(--color-error)",
                      }}
                    >
                      {evidenceData.verdict}
                    </span>
                  </div>

                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", marginBottom: "16px" }}>
                    {/* Request Column */}
                    <div>
                      <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--text-muted)", marginBottom: "6px" }}>
                        HTTP REQUEST (SENT)
                      </div>
                      <div style={{ fontSize: "11px", fontFamily: "DM Mono, monospace", background: "var(--bg-primary)", padding: "10px", borderRadius: "6px", color: "var(--text-main)" }}>
                        <div style={{ color: "var(--accent-primary)", marginBottom: "4px" }}>
                          {evidenceData.http_method} {evidenceData.target_url}
                        </div>
                        <div style={{ fontSize: "10px", color: "var(--text-dim)", marginBottom: "6px" }}>
                          {JSON.stringify(evidenceData.request_headers)}
                        </div>
                        <pre style={{ margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                          {evidenceData.request_body}
                        </pre>
                      </div>
                    </div>

                    {/* Response Column */}
                    <div>
                      <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--text-muted)", marginBottom: "6px" }}>
                        HTTP RESPONSE (RECEIVED)
                      </div>
                      <div style={{ fontSize: "11px", fontFamily: "DM Mono, monospace", background: "var(--bg-primary)", padding: "10px", borderRadius: "6px", color: "var(--text-main)" }}>
                        <div style={{ color: evidenceData.response_status_code === 200 ? "var(--color-online)" : "var(--color-claude)", marginBottom: "4px" }}>
                          HTTP {evidenceData.response_status_code} ({evidenceData.response_latency_ms?.toFixed(1) || 0}ms)
                        </div>
                        <pre style={{ margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-all", maxHeight: "200px", overflowY: "auto" }}>
                          {evidenceData.response_body || "(empty body)"}
                        </pre>
                      </div>
                    </div>
                  </div>

                  {/* Cryptographic SHA-256 Digest Verification */}
                  <div style={{ borderTop: "1px solid var(--border-subtle)", paddingTop: "12px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <div>
                      <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--text-muted)" }}>
                        CRYPTOGRAPHIC HMAC-SHA256 EVIDENCE DIGEST
                      </div>
                      <div style={{ fontSize: "11px", fontFamily: "DM Mono, monospace", color: "var(--accent-cyan)", marginTop: "2px" }}>
                        {evidenceData.evidence_sha256}
                      </div>
                    </div>

                    <button
                      onClick={() => handleVerifyIntegrity(evidenceData.execution_id)}
                      disabled={evidenceVerifying}
                      style={{
                        padding: "6px 12px",
                        borderRadius: "6px",
                        background: "rgba(99,102,241,0.2)",
                        border: "1px solid var(--accent-primary)",
                        color: "var(--text-main)",
                        fontSize: "11px",
                        fontWeight: "600",
                        cursor: "pointer",
                      }}
                    >
                      {evidenceVerifying ? "Verifying..." : "🛡️ Verify Signature"}
                    </button>
                  </div>

                  {evidenceIntegrity && (
                    <div
                      style={{
                        marginTop: "10px",
                        padding: "8px 12px",
                        borderRadius: "6px",
                        background: evidenceIntegrity.match ? "rgba(34,197,94,0.15)" : "rgba(239,68,68,0.15)",
                        border: `1px solid ${evidenceIntegrity.match ? "rgba(34,197,94,0.3)" : "rgba(239,68,68,0.3)"}`,
                        fontSize: "11px",
                        color: evidenceIntegrity.match ? "var(--color-online)" : "var(--color-error)",
                        display: "flex",
                        alignItems: "center",
                        gap: "6px",
                      }}
                    >
                      <span>{evidenceIntegrity.match ? "✅ Signature Valid: Wire evidence authenticity cryptographically proven." : "❌ Signature Mismatch: Content modified since capture."}</span>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}



          {/* TAB 4: Executive Assessment Report */}
          {activeTab === "report" && (
            <div>
              {!report ? (
                <div style={{ padding: "40px 20px", textAlign: "center", color: "var(--text-dim)" }}>
                  Execute an adaptive security testing plan to view the executive assessment report.
                </div>
              ) : (
                <div>
                  {/* Metric Cards Row */}
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "14px", marginBottom: "16px" }}>
                    <div style={{ background: "var(--bg-surface-elevated)", border: "1px solid var(--border-subtle)", borderRadius: "8px", padding: "14px", textAlign: "center" }}>
                      <div style={{ fontSize: "11px", color: "var(--text-muted)", fontWeight: "600" }}>EVALUABLE RESILIENCE</div>
                      <div style={{ fontSize: "28px", fontWeight: "800", color: report.overall_resilience_score_percent >= 80 ? "var(--color-online)" : "var(--color-error)", marginTop: "4px" }}>
                        {report.overall_resilience_score_percent.toFixed(1)}%
                      </div>
                      <div style={{ fontSize: "10px", color: "var(--text-dim)", marginTop: "4px", fontFamily: "DM Mono, monospace" }}>
                        BLOCKED / (BLOCKED + VULNERABLE + PARTIAL)
                      </div>
                    </div>

                    <div style={{ background: "var(--bg-surface-elevated)", border: "1px solid var(--border-subtle)", borderRadius: "8px", padding: "14px", textAlign: "center" }}>
                      <div style={{ fontSize: "11px", color: "var(--text-muted)", fontWeight: "600" }}>EVALUABLE COVERAGE</div>
                      <div style={{ fontSize: "28px", fontWeight: "800", color: "var(--text-main)", marginTop: "4px" }}>
                        {report.evaluable_coverage_percent?.toFixed(1) || "100.0"}%
                      </div>
                      <div style={{ fontSize: "10px", color: "var(--text-dim)", marginTop: "4px" }}>
                        {report.evaluable_scenarios ?? report.total_scenarios_tested} of {report.total_scenarios_tested} Scenarios Evaluable
                      </div>
                    </div>

                    <div style={{ background: "var(--bg-surface-elevated)", border: "1px solid var(--border-subtle)", borderRadius: "8px", padding: "14px", textAlign: "center" }}>
                      <div style={{ fontSize: "11px", color: "var(--text-muted)", fontWeight: "600" }}>INFRASTRUCTURE ERROR RATE</div>
                      <div style={{ fontSize: "28px", fontWeight: "800", color: report.infrastructure_error_rate_percent > 0 ? "var(--color-claude)" : "var(--color-online)", marginTop: "4px" }}>
                        {report.infrastructure_error_rate_percent?.toFixed(1) || "0.0"}%
                      </div>
                      <div style={{ fontSize: "10px", color: "var(--text-dim)", marginTop: "4px" }}>
                        {report.error_scenarios || 0} Error / Timeout Scenarios
                      </div>
                    </div>

                    <div style={{ background: "var(--bg-surface-elevated)", border: "1px solid var(--border-subtle)", borderRadius: "8px", padding: "14px", textAlign: "center" }}>
                      <div style={{ fontSize: "11px", color: "var(--text-muted)", fontWeight: "600" }}>CONFIRMED VULNERABILITIES</div>
                      <div style={{ fontSize: "28px", fontWeight: "800", color: report.total_vulnerabilities_confirmed === 0 ? "var(--color-online)" : "var(--color-error)", marginTop: "4px" }}>
                        {report.total_vulnerabilities_confirmed}
                      </div>
                      <div style={{ fontSize: "10px", color: "var(--text-dim)", marginTop: "4px" }}>
                        Verified via Multi-Turn Confirmation Probes
                      </div>
                    </div>
                  </div>

                  {/* Granular Verdict Breakdown Row */}
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: "10px", marginBottom: "20px" }}>
                    <div style={{ background: "rgba(34,197,94,0.08)", border: "1px solid rgba(34,197,94,0.25)", borderRadius: "6px", padding: "10px", textAlign: "center" }}>
                      <div style={{ fontSize: "10px", fontWeight: "700", color: "var(--color-online)" }}>BLOCKED (SECURE)</div>
                      <div style={{ fontSize: "20px", fontWeight: "800", color: "var(--color-online)", marginTop: "2px" }}>
                        {report.blocked_scenarios ?? (report.total_scenarios_tested - report.total_vulnerabilities_confirmed)}
                      </div>
                    </div>
                    <div style={{ background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.25)", borderRadius: "6px", padding: "10px", textAlign: "center" }}>
                      <div style={{ fontSize: "10px", fontWeight: "700", color: "var(--color-error)" }}>VULNERABLE (CONFIRMED)</div>
                      <div style={{ fontSize: "20px", fontWeight: "800", color: "var(--color-error)", marginTop: "2px" }}>
                        {report.vulnerable_scenarios ?? report.total_vulnerabilities_confirmed}
                      </div>
                    </div>
                    <div style={{ background: "rgba(245,158,11,0.08)", border: "1px solid rgba(245,158,11,0.25)", borderRadius: "6px", padding: "10px", textAlign: "center" }}>
                      <div style={{ fontSize: "10px", fontWeight: "700", color: "var(--color-claude)" }}>PARTIAL (BORDERLINE)</div>
                      <div style={{ fontSize: "20px", fontWeight: "800", color: "var(--color-claude)", marginTop: "2px" }}>
                        {report.partial_scenarios || 0}
                      </div>
                    </div>
                    <div style={{ background: "rgba(168,85,247,0.08)", border: "1px solid rgba(168,85,247,0.25)", borderRadius: "6px", padding: "10px", textAlign: "center" }}>
                      <div style={{ fontSize: "10px", fontWeight: "700", color: "var(--accent-primary)" }}>INCONCLUSIVE / ECHO</div>
                      <div style={{ fontSize: "20px", fontWeight: "800", color: "var(--accent-primary)", marginTop: "2px" }}>
                        {report.inconclusive_scenarios || 0}
                      </div>
                    </div>
                    <div style={{ background: "rgba(148,163,184,0.08)", border: "1px solid rgba(148,163,184,0.25)", borderRadius: "6px", padding: "10px", textAlign: "center" }}>
                      <div style={{ fontSize: "10px", fontWeight: "700", color: "var(--text-dim)" }}>INFRA ERROR / TIMEOUT</div>
                      <div style={{ fontSize: "20px", fontWeight: "800", color: "var(--text-dim)", marginTop: "2px" }}>
                        {report.error_scenarios || 0}
                      </div>
                    </div>
                  </div>

                  {/* Cryptographic Wire Evidence Integrity Banner */}
                  <div style={{ background: report.evidence_integrity_verified ? "rgba(34,197,94,0.08)" : "rgba(239,68,68,0.08)", border: `1px solid ${report.evidence_integrity_verified ? "rgba(34,197,94,0.25)" : "rgba(239,68,68,0.25)"}`, borderRadius: "6px", padding: "10px 14px", marginBottom: "20px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                      <span style={{ fontSize: "14px" }}>{report.evidence_integrity_verified ? "🛡️" : "⚠️"}</span>
                      <span style={{ fontSize: "12px", fontWeight: "700", color: report.evidence_integrity_verified ? "var(--color-online)" : "var(--color-error)" }}>
                        {report.evidence_integrity_verified
                          ? "HMAC-SHA256 Wire Evidence Verified: All executed HTTP wire records cryptographically authenticated."
                          : "Integrity Verification Warning: Stored wire evidence hash mismatch detected."}
                      </span>
                    </div>
                    <span style={{ fontSize: "11px", fontFamily: "DM Mono, monospace", color: "var(--text-muted)" }}>
                      {report.total_turns_dispatched} Wire Turns Dispatched
                    </span>
                  </div>

                  {/* Remediation Guidance */}
                  {report.remediation_recommendations?.length > 0 && (
                    <div style={{ marginBottom: "20px" }}>
                      <h3 style={{ fontSize: "13px", fontWeight: "700", color: "var(--accent-cyan)", marginBottom: "10px", textTransform: "uppercase" }}>
                        🛡️ Recommended Hardening Directives
                      </h3>
                      <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                        {report.remediation_recommendations.map((rem, idx) => (
                          <div key={idx} style={{ background: "var(--bg-surface-elevated)", border: "1px solid var(--border-subtle)", borderRadius: "8px", padding: "12px 14px" }}>
                            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
                              <span style={{ padding: "2px 6px", borderRadius: "4px", background: "rgba(239,68,68,0.2)", color: "var(--color-error)", fontSize: "10px", fontWeight: "700" }}>
                                {rem.risk_id}
                              </span>
                              <strong style={{ fontSize: "13px", color: "var(--text-main)" }}>{rem.title}</strong>
                            </div>
                            <p style={{ fontSize: "12px", color: "var(--text-muted)", margin: 0 }}>{rem.remediation}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}



          {/* TAB 5 (Phase D): Application Context & Reconnaissance */}
          {activeTab === "context" && (
            <div>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
                <div>
                  <h3 style={{ fontSize: "15px", fontWeight: "700", color: "var(--text-main)", margin: 0 }}>
                    🌐 Target Application Context Intelligence
                  </h3>
                  <p style={{ fontSize: "12px", color: "var(--text-muted)", margin: "4px 0 0 0" }}>
                    Controlled reconnaissance discovering exposed endpoints, schemas, authentication, and security controls.
                  </p>
                </div>
                <div style={{ display: "flex", gap: "8px" }}>
                  <button
                    onClick={handleDiscoverContext}
                    disabled={isDiscoveringContext}
                    style={{
                      padding: "8px 14px",
                      borderRadius: "6px",
                      background: "var(--accent-primary)",
                      color: "#fff",
                      border: "none",
                      fontSize: "12px",
                      fontWeight: "600",
                      cursor: isDiscoveringContext ? "not-allowed" : "pointer",
                      display: "flex",
                      alignItems: "center",
                      gap: "6px",
                    }}
                  >
                    {isDiscoveringContext ? "Discovering..." : "🔍 Discover Local Context"}
                  </button>
                  <button
                    onClick={() => setShowOpenApiModal(true)}
                    style={{
                      padding: "8px 14px",
                      borderRadius: "6px",
                      background: "var(--bg-surface-elevated)",
                      color: "var(--accent-cyan)",
                      border: "1px solid var(--accent-cyan)",
                      fontSize: "12px",
                      fontWeight: "600",
                      cursor: "pointer",
                    }}
                  >
                    📥 Import OpenAPI Spec
                  </button>
                </div>
              </div>

              {/* OpenAPI Modal */}
              {showOpenApiModal && (
                <div style={{ background: "var(--bg-surface-elevated)", border: "1px solid var(--border-subtle)", borderRadius: "8px", padding: "16px", marginBottom: "16px" }}>
                  <h4 style={{ fontSize: "13px", fontWeight: "700", color: "var(--text-main)", marginBottom: "8px" }}>
                    Paste OpenAPI 3.0 / Swagger JSON Specification
                  </h4>
                  <textarea
                    value={openApiSpecText}
                    onChange={(e) => setOpenApiSpecText(e.target.value)}
                    rows={6}
                    placeholder='{"openapi": "3.0.0", "info": {"title": "My Secured API"}, "paths": {...}}'
                    style={{
                      width: "100%",
                      padding: "10px",
                      borderRadius: "6px",
                      background: "var(--bg-primary)",
                      border: "1px solid var(--border-subtle)",
                      color: "var(--text-main)",
                      fontFamily: "DM Mono, monospace",
                      fontSize: "11px",
                      marginBottom: "10px",
                    }}
                  />
                  <div style={{ display: "flex", justifyContent: "flex-end", gap: "8px" }}>
                    <button
                      onClick={() => setShowOpenApiModal(false)}
                      style={{ padding: "6px 12px", borderRadius: "6px", background: "transparent", border: "1px solid var(--border-subtle)", color: "var(--text-muted)", fontSize: "12px", cursor: "pointer" }}
                    >
                      Cancel
                    </button>
                    <button
                      onClick={handleImportOpenApi}
                      disabled={isDiscoveringContext}
                      style={{ padding: "6px 12px", borderRadius: "6px", background: "var(--accent-primary)", border: "none", color: "#fff", fontSize: "12px", fontWeight: "600", cursor: "pointer" }}
                    >
                      Parse & Import
                    </button>
                  </div>
                </div>
              )}

              {!discoveredContext ? (
                <div style={{ padding: "40px 20px", textAlign: "center", color: "var(--text-dim)", background: "var(--bg-surface-elevated)", borderRadius: "8px" }}>
                  Click "Discover Local Context" to inspect routes and security surfaces for {targetUrl}.
                </div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
                  {/* Scope & Confidence Summary */}
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "12px" }}>
                    <div style={{ background: "var(--bg-surface-elevated)", border: "1px solid var(--border-subtle)", borderRadius: "8px", padding: "12px" }}>
                      <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>TARGET SCOPE</div>
                      <div style={{ fontSize: "14px", fontWeight: "700", color: "var(--text-main)", marginTop: "2px", fontFamily: "DM Mono, monospace" }}>
                        {discoveredContext.target_scope}
                      </div>
                    </div>
                    <div style={{ background: "var(--bg-surface-elevated)", border: "1px solid var(--border-subtle)", borderRadius: "8px", padding: "12px" }}>
                      <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>DISCOVERED ROUTES</div>
                      <div style={{ fontSize: "14px", fontWeight: "700", color: "var(--accent-cyan)", marginTop: "2px" }}>
                        {discoveredContext.discovered_endpoints.length} Active Endpoints
                      </div>
                    </div>
                    <div style={{ background: "var(--bg-surface-elevated)", border: "1px solid var(--border-subtle)", borderRadius: "8px", padding: "12px" }}>
                      <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>SECURITY CONTROLS</div>
                      <div style={{ fontSize: "14px", fontWeight: "700", color: "var(--color-online)", marginTop: "2px" }}>
                        {discoveredContext.discovered_security_controls.length} Controls Identified
                      </div>
                    </div>
                    <div style={{ background: "var(--bg-surface-elevated)", border: "1px solid var(--border-subtle)", borderRadius: "8px", padding: "12px" }}>
                      <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>CONTEXT CONFIDENCE</div>
                      <div style={{ fontSize: "14px", fontWeight: "700", color: "var(--accent-primary)", marginTop: "2px" }}>
                        {(discoveredContext.context_confidence * 100).toFixed(0)}% Confidence
                      </div>
                    </div>
                  </div>

                  {/* Detected Components & Security Controls Badges */}
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "14px" }}>
                    <div style={{ background: "var(--bg-surface-elevated)", border: "1px solid var(--border-subtle)", borderRadius: "8px", padding: "14px" }}>
                      <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--text-muted)", marginBottom: "8px" }}>
                        DETECTED SYSTEM COMPONENTS
                      </div>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                        {discoveredContext.discovered_components.map((c, i) => (
                          <span key={i} style={{ padding: "4px 8px", borderRadius: "4px", background: "rgba(99,102,241,0.15)", color: "var(--accent-cyan)", fontSize: "11px" }}>
                            📦 {c}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div style={{ background: "var(--bg-surface-elevated)", border: "1px solid var(--border-subtle)", borderRadius: "8px", padding: "14px" }}>
                      <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--text-muted)", marginBottom: "8px" }}>
                        DETECTED SECURITY CONTROLS
                      </div>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                        {discoveredContext.discovered_security_controls.map((s, i) => (
                          <span key={i} style={{ padding: "4px 8px", borderRadius: "4px", background: "rgba(34,197,94,0.12)", color: "var(--color-online)", fontSize: "11px" }}>
                            🛡️ {s}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Discovered Endpoints Table */}
                  <div style={{ background: "var(--bg-surface-elevated)", border: "1px solid var(--border-subtle)", borderRadius: "8px", overflow: "hidden" }}>
                    <div style={{ padding: "12px 14px", borderBottom: "1px solid var(--border-subtle)", fontWeight: "700", fontSize: "12px", color: "var(--text-muted)" }}>
                      DISCOVERED ENDPOINT REGISTRY
                    </div>
                    <div style={{ maxHeight: "300px", overflowY: "auto" }}>
                      {discoveredContext.discovered_endpoints.map((ep, idx) => (
                        <div key={idx} style={{ padding: "10px 14px", borderBottom: "1px solid var(--border-subtle)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                          <div>
                            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                              <span style={{ padding: "2px 6px", borderRadius: "4px", background: ep.methods.includes("POST") ? "rgba(99,102,241,0.2)" : "rgba(34,197,94,0.2)", color: ep.methods.includes("POST") ? "var(--accent-primary)" : "var(--color-online)", fontSize: "10px", fontWeight: "700" }}>
                                {ep.methods.join(", ")}
                              </span>
                              <span style={{ fontSize: "12px", fontFamily: "DM Mono, monospace", color: "var(--text-main)", fontWeight: "600" }}>
                                {ep.path}
                              </span>
                              {ep.is_tested_surface && (
                                <span style={{ padding: "1px 6px", borderRadius: "4px", background: "rgba(245,158,11,0.15)", color: "var(--color-claude)", fontSize: "9px", fontWeight: "700" }}>
                                  TARGET SURFACE
                                </span>
                              )}
                            </div>
                            <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "3px" }}>
                              {ep.description}
                            </div>
                          </div>
                          <span style={{ fontSize: "10px", color: "var(--text-dim)", fontFamily: "DM Mono, monospace" }}>
                            {ep.auth_required ? "🔒 Auth Required" : "🔓 Public"}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}



          {/* TAB 6 (Phase D): OWASP 20-Risk Correlation Matrix */}
          {activeTab === "correlation" && (
            <div>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
                <div>
                  <h3 style={{ fontSize: "15px", fontWeight: "700", color: "var(--text-main)", margin: 0 }}>
                    🕸️ OWASP 20-Risk Correlation & Escalation Graph
                  </h3>
                  <p style={{ fontSize: "12px", color: "var(--text-muted)", margin: "4px 0 0 0" }}>
                    Full 20-risk mapping: 10 OWASP Top 10 for LLM Applications + 10 OWASP Top 10 for Agentic AI.
                  </p>
                </div>
                <button
                  onClick={handleFetchCorrelationGraph}
                  disabled={isFetchingCorrelation}
                  style={{
                    padding: "8px 14px",
                    borderRadius: "6px",
                    background: "var(--accent-primary)",
                    color: "#fff",
                    border: "none",
                    fontSize: "12px",
                    fontWeight: "600",
                    cursor: "pointer",
                  }}
                >
                  {isFetchingCorrelation ? "Updating..." : "🔄 Refresh Graph"}
                </button>
              </div>

              {/* Hypothesis Disclaimer Banner */}
              <div style={{ background: "rgba(245,158,11,0.1)", border: "1px solid rgba(245,158,11,0.3)", borderRadius: "8px", padding: "10px 14px", marginBottom: "16px", fontSize: "11px", color: "var(--color-claude)", display: "flex", alignItems: "center", gap: "8px" }}>
                <span>⚠️</span>
                <span>
                  <strong>Escalation Hypothesis Notice:</strong> Identified risk relationships represent attack progression hypotheses for testing. They do not constitute verified vulnerabilities until verified by real HTTP test executions.
                </span>
              </div>

              {!correlationGraph ? (
                <div style={{ padding: "40px 20px", textAlign: "center", color: "var(--text-dim)" }}>
                  Loading 20-risk correlation matrix...
                </div>
              ) : (
                <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: "16px" }}>
                  {/* Left Column: 20 Risks Grid */}
                  <div>
                    <div style={{ fontSize: "12px", fontWeight: "700", color: "var(--text-muted)", marginBottom: "8px" }}>
                      MAPPED RISKS ({correlationGraph.total_risks_mapped})
                    </div>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px", maxHeight: "450px", overflowY: "auto", paddingRight: "4px" }}>
                      {correlationGraph.nodes.map((node) => {
                        const isSelected = selectedCorrelationRisk === node.id;
                        return (
                          <div
                            key={node.id}
                            onClick={() => setSelectedCorrelationRisk(node.id)}
                            style={{
                              background: isSelected ? "rgba(99,102,241,0.2)" : "var(--bg-surface-elevated)",
                              border: `1px solid ${isSelected ? "var(--accent-primary)" : "var(--border-subtle)"}`,
                              borderRadius: "8px",
                              padding: "10px",
                              cursor: "pointer",
                              transition: "all 0.15s ease",
                            }}
                          >
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
                              <span style={{ fontSize: "11px", fontWeight: "800", color: isSelected ? "var(--accent-cyan)" : "var(--text-main)" }}>
                                {node.id}
                              </span>
                              <span
                                style={{
                                  fontSize: "9px",
                                  fontWeight: "700",
                                  padding: "1px 5px",
                                  borderRadius: "4px",
                                  background: node.severity === "CRITICAL" ? "rgba(239,68,68,0.2)" : "rgba(245,158,11,0.2)",
                                  color: node.severity === "CRITICAL" ? "var(--color-error)" : "var(--color-claude)",
                                }}
                              >
                                {node.severity}
                              </span>
                            </div>
                            <div style={{ fontSize: "11px", color: "var(--text-muted)", fontWeight: "600", marginBottom: "2px" }}>
                              {node.label.split(":")[1]?.trim()}
                            </div>
                            <div style={{ fontSize: "10px", color: "var(--text-dim)" }}>
                              {node.category}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  {/* Right Column: Relationships for Selected Risk */}
                  <div>
                    <div style={{ fontSize: "12px", fontWeight: "700", color: "var(--text-muted)", marginBottom: "8px" }}>
                      DEPENDENCY & ESCALATION PATHS FOR {selectedCorrelationRisk}
                    </div>
                    <div style={{ display: "flex", flexDirection: "column", gap: "10px", maxHeight: "450px", overflowY: "auto" }}>
                      {correlationGraph.edges
                        .filter((e) => e.source_risk === selectedCorrelationRisk || e.related_risk === selectedCorrelationRisk)
                        .map((edge, idx) => (
                          <div
                            key={idx}
                            style={{
                              background: "var(--bg-surface-elevated)",
                              border: "1px solid var(--border-subtle)",
                              borderRadius: "8px",
                              padding: "12px",
                            }}
                          >
                            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
                              <span style={{ fontWeight: "800", fontSize: "12px", color: "var(--accent-cyan)" }}>
                                {edge.source_risk}
                              </span>
                              <span style={{ fontSize: "10px", padding: "2px 6px", borderRadius: "4px", background: "rgba(99,102,241,0.2)", color: "var(--accent-primary)", fontWeight: "700" }}>
                                {edge.relationship_type.toUpperCase()}
                              </span>
                              <span style={{ fontWeight: "800", fontSize: "12px", color: "var(--accent-cyan)" }}>
                                ➔ {edge.related_risk}
                              </span>
                              <span style={{ marginLeft: "auto", fontSize: "10px", color: "var(--text-dim)", fontFamily: "DM Mono, monospace" }}>
                                {(edge.correlation_confidence * 100).toFixed(0)}% Conf
                              </span>
                            </div>
                            <div style={{ fontSize: "11px", color: "var(--text-muted)", marginBottom: "4px" }}>
                              <strong>Prerequisite:</strong> {edge.prerequisite || "None specified"}
                            </div>
                            <div style={{ fontSize: "11px", color: "var(--text-dim)" }}>
                              {edge.rationale}
                            </div>
                          </div>
                        ))}
                      {correlationGraph.edges.filter((e) => e.source_risk === selectedCorrelationRisk || e.related_risk === selectedCorrelationRisk).length === 0 && (
                        <div style={{ padding: "20px", textAlign: "center", color: "var(--text-dim)", background: "var(--bg-surface-elevated)", borderRadius: "8px" }}>
                          No direct dependencies for {selectedCorrelationRisk} in catalog.
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}



          {/* TAB 7 (Phase D): Multi-Risk Attack Chains Orchestrator */}
          {activeTab === "attack_chains" && (
            <div>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
                <div>
                  <h3 style={{ fontSize: "15px", fontWeight: "700", color: "var(--text-main)", margin: 0 }}>
                    ⚡ Multi-Risk Attack Chain Orchestration
                  </h3>
                  <p style={{ fontSize: "12px", color: "var(--text-muted)", margin: "4px 0 0 0" }}>
                    Automated multi-stage sequential exploit progression with HMAC-SHA256 authenticated wire signatures.
                  </p>
                </div>
              </div>

              {/* Chain Builder Controls */}
              <div style={{ background: "var(--bg-surface-elevated)", border: "1px solid var(--border-subtle)", borderRadius: "8px", padding: "14px", marginBottom: "16px" }}>
                <div style={{ display: "grid", gridTemplateColumns: "3fr 1.5fr auto", gap: "12px", alignItems: "flex-end" }}>
                  <div>
                    <label style={{ display: "block", fontSize: "11px", fontWeight: "700", color: "var(--text-muted)", marginBottom: "4px" }}>
                      ATTACK CHAIN DIRECTIVE
                    </label>
                    <input
                      type="text"
                      value={chainCommand}
                      onChange={(e) => setChainCommand(e.target.value)}
                      placeholder="e.g. Evaluate whether LLM01 unlocks agent goal hijacking ASI01"
                      style={{
                        width: "100%",
                        padding: "8px 12px",
                        borderRadius: "6px",
                        background: "var(--bg-primary)",
                        border: "1px solid var(--border-subtle)",
                        color: "var(--text-main)",
                        fontSize: "12px",
                      }}
                    />
                  </div>

                  <div>
                    <label style={{ display: "block", fontSize: "11px", fontWeight: "700", color: "var(--text-muted)", marginBottom: "4px" }}>
                      TARGET STAGE
                    </label>
                    <select
                      value={chainStage}
                      onChange={(e) => setChainStage(e.target.value)}
                      style={{
                        width: "100%",
                        padding: "8px 12px",
                        borderRadius: "6px",
                        background: "var(--bg-primary)",
                        border: "1px solid var(--border-subtle)",
                        color: "var(--text-main)",
                        fontSize: "12px",
                      }}
                    >
                      <option value="POST_MITIGATION">POST_MITIGATION (Hardened)</option>
                      <option value="BASELINE">BASELINE (Vulnerable)</option>
                    </select>
                  </div>

                  <button
                    onClick={handleGenerateAttackChain}
                    disabled={isGeneratingChain}
                    style={{
                      padding: "8px 16px",
                      borderRadius: "6px",
                      background: "var(--accent-primary)",
                      color: "#fff",
                      border: "none",
                      fontSize: "12px",
                      fontWeight: "700",
                      cursor: isGeneratingChain ? "not-allowed" : "pointer",
                    }}
                  >
                    {isGeneratingChain ? "Synthesizing..." : "⚡ Generate Attack Chain"}
                  </button>
                </div>

                {/* Risk Selection Pills for Chain */}
                <div style={{ marginTop: "12px" }}>
                  <span style={{ fontSize: "11px", color: "var(--text-muted)", marginRight: "8px" }}>Sequence Risks:</span>
                  {["LLM01", "ASI01", "ASI02", "LLM02", "ASI03", "ASI05"].map((r) => {
                    const isSelected = chainRisks.includes(r);
                    return (
                      <button
                        key={r}
                        onClick={() => toggleChainRisk(r)}
                        style={{
                          marginRight: "6px",
                          padding: "2px 8px",
                          borderRadius: "4px",
                          background: isSelected ? "rgba(99,102,241,0.25)" : "var(--bg-primary)",
                          border: `1px solid ${isSelected ? "var(--accent-primary)" : "var(--border-subtle)"}`,
                          color: isSelected ? "var(--text-main)" : "var(--text-dim)",
                          fontSize: "11px",
                          cursor: "pointer",
                        }}
                      >
                        {r}
                      </button>
                    );
                  })}
                </div>
              </div>

              {!attackChain ? (
                <div style={{ padding: "40px 20px", textAlign: "center", color: "var(--text-dim)", background: "var(--bg-surface-elevated)", borderRadius: "8px" }}>
                  Generate a multi-risk attack chain to inspect sequential execution steps.
                </div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
                  {/* Chain Overview Banner */}
                  <div style={{ background: "var(--bg-surface-elevated)", border: "1px solid var(--border-subtle)", borderRadius: "8px", padding: "14px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                      <div>
                        <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--accent-cyan)" }}>{attackChain.chain_id}</div>
                        <h4 style={{ fontSize: "15px", fontWeight: "800", color: "var(--text-main)", margin: "2px 0 0 0" }}>
                          {attackChain.chain_name}
                        </h4>
                      </div>
                      <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                        <span
                          style={{
                            padding: "3px 10px",
                            borderRadius: "12px",
                            fontSize: "11px",
                            fontWeight: "700",
                            background: attackChain.execution_status === "COMPLETED" ? "rgba(34,197,94,0.15)" : "rgba(99,102,241,0.15)",
                            color: attackChain.execution_status === "COMPLETED" ? "var(--color-online)" : "var(--accent-cyan)",
                          }}
                        >
                          {attackChain.execution_status}
                        </span>
                        <button
                          onClick={handleExecuteAttackChain}
                          disabled={isExecutingChain}
                          style={{
                            padding: "6px 14px",
                            borderRadius: "6px",
                            background: "var(--accent-cyan)",
                            color: "#0f172a",
                            border: "none",
                            fontSize: "12px",
                            fontWeight: "700",
                            cursor: isExecutingChain ? "not-allowed" : "pointer",
                          }}
                        >
                          {isExecutingChain ? "Executing On Wire..." : "🚀 Execute Attack Chain (HTTP Wire)"}
                        </button>
                      </div>
                    </div>
                    <p style={{ fontSize: "12px", color: "var(--text-muted)", margin: 0 }}>
                      {attackChain.description}
                    </p>

                    {/* Final Assessment if completed */}
                    {attackChain.final_assessment !== "PENDING" && (
                      <div
                        style={{
                          marginTop: "12px",
                          padding: "10px 14px",
                          borderRadius: "6px",
                          background: attackChain.final_assessment.includes("DEFENDED") ? "rgba(34,197,94,0.15)" : "rgba(239,68,68,0.15)",
                          border: `1px solid ${attackChain.final_assessment.includes("DEFENDED") ? "rgba(34,197,94,0.3)" : "rgba(239,68,68,0.3)"}`,
                          color: attackChain.final_assessment.includes("DEFENDED") ? "var(--color-online)" : "var(--color-error)",
                          fontSize: "12px",
                          fontWeight: "700",
                        }}
                      >
                        🛡️ Final Assessment: {attackChain.final_assessment}
                      </div>
                    )}
                  </div>

                  {/* Sequential Steps Cards */}
                  <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                    {attackChain.execution_steps.map((step) => (
                      <div
                        key={step.step_id}
                        style={{
                          background: "var(--bg-surface-elevated)",
                          border: "1px solid var(--border-subtle)",
                          borderRadius: "8px",
                          padding: "12px 14px",
                        }}
                      >
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                            <span style={{ padding: "2px 6px", borderRadius: "4px", background: "var(--bg-primary)", color: "var(--text-main)", fontSize: "11px", fontWeight: "800" }}>
                              Step {step.step_order}
                            </span>
                            <span style={{ padding: "2px 6px", borderRadius: "4px", background: "rgba(99,102,241,0.2)", color: "var(--accent-primary)", fontSize: "11px", fontWeight: "700" }}>
                              {step.risk_id}
                            </span>
                            <span style={{ fontSize: "12px", fontFamily: "DM Mono, monospace", color: "var(--text-main)", fontWeight: "600" }}>
                              {step.http_method} {step.target_endpoint}
                            </span>
                          </div>

                          {step.verdict && (
                            <span
                              style={{
                                padding: "2px 8px",
                                borderRadius: "10px",
                                fontSize: "10px",
                                fontWeight: "700",
                                background: step.verdict === "BLOCKED" ? "rgba(34,197,94,0.15)" : "rgba(239,68,68,0.15)",
                                color: step.verdict === "BLOCKED" ? "var(--color-online)" : "var(--color-error)",
                              }}
                            >
                              {step.verdict}
                            </span>
                          )}
                        </div>

                        <div style={{ fontSize: "11px", color: "var(--text-muted)", marginBottom: "6px" }}>
                          {step.payload_description}
                        </div>

                        <div style={{ fontSize: "11px", fontFamily: "DM Mono, monospace", background: "var(--bg-primary)", padding: "6px 8px", borderRadius: "4px", color: "var(--accent-cyan)", marginBottom: "6px", overflowX: "auto" }}>
                          {JSON.stringify(step.payload_body)}
                        </div>

                        {step.actual_behavior && (
                          <div style={{ fontSize: "11px", color: "var(--text-dim)", marginTop: "4px" }}>
                            <strong>Result:</strong> {step.actual_behavior}
                          </div>
                        )}

                        {step.evidence_sha256 && (
                          <div style={{ fontSize: "10px", color: "var(--text-dim)", fontFamily: "DM Mono, monospace", marginTop: "4px" }}>
                            Wire Sig: {step.evidence_sha256}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}



          {/* TAB 8 (Phase D): Root Cause Analysis, CVSS v3.1 & Remediation */}
          {activeTab === "rca_remediation" && (
            <div>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
                <div>
                  <h3 style={{ fontSize: "15px", fontWeight: "700", color: "var(--text-main)", margin: 0 }}>
                    🔬 Root Cause Analysis (RCA), CVSS v3.1 & Remediation Intelligence
                  </h3>
                  <p style={{ fontSize: "12px", color: "var(--text-muted)", margin: "4px 0 0 0" }}>
                    Identify failed security controls, crossed trust boundaries, transparent CVSS base scores, and actionable code fixes.
                  </p>
                </div>
              </div>

              {/* RCA Controls */}
              <div style={{ background: "var(--bg-surface-elevated)", border: "1px solid var(--border-subtle)", borderRadius: "8px", padding: "14px", marginBottom: "16px" }}>
                <div style={{ display: "grid", gridTemplateColumns: "1.5fr 1.5fr 1.5fr auto", gap: "12px", alignItems: "flex-end" }}>
                  <div>
                    <label style={{ display: "block", fontSize: "11px", fontWeight: "700", color: "var(--text-muted)", marginBottom: "4px" }}>
                      RISK CATEGORY
                    </label>
                    <select
                      value={selectedRcaRisk}
                      onChange={(e) => {
                        setSelectedRcaRisk(e.target.value);
                        setSelectedRcaScenario(`${e.target.value}-01`);
                      }}
                      style={{
                        width: "100%",
                        padding: "8px",
                        borderRadius: "6px",
                        background: "var(--bg-primary)",
                        border: "1px solid var(--border-subtle)",
                        color: "var(--text-main)",
                        fontSize: "12px",
                      }}
                    >
                      <option value="LLM01">LLM01 - Prompt Injection</option>
                      <option value="LLM02">LLM02 - Sensitive Information Disclosure</option>
                      <option value="ASI01">ASI01 - Agent Goal Hijacking</option>
                      <option value="ASI02">ASI02 - Tool Misuse & Sandbox Traversal</option>
                    </select>
                  </div>

                  <div>
                    <label style={{ display: "block", fontSize: "11px", fontWeight: "700", color: "var(--text-muted)", marginBottom: "4px" }}>
                      SCENARIO ID
                    </label>
                    <input
                      type="text"
                      value={selectedRcaScenario}
                      onChange={(e) => setSelectedRcaScenario(e.target.value)}
                      style={{
                        width: "100%",
                        padding: "8px",
                        borderRadius: "6px",
                        background: "var(--bg-primary)",
                        border: "1px solid var(--border-subtle)",
                        color: "var(--text-main)",
                        fontSize: "12px",
                      }}
                    />
                  </div>

                  <div>
                    <label style={{ display: "block", fontSize: "11px", fontWeight: "700", color: "var(--text-muted)", marginBottom: "4px" }}>
                      EVALUATION OUTCOME
                    </label>
                    <select
                      value={selectedRcaVerdict}
                      onChange={(e) => setSelectedRcaVerdict(e.target.value)}
                      style={{
                        width: "100%",
                        padding: "8px",
                        borderRadius: "6px",
                        background: "var(--bg-primary)",
                        border: "1px solid var(--border-subtle)",
                        color: "var(--text-main)",
                        fontSize: "12px",
                      }}
                    >
                      <option value="VULNERABLE">VULNERABLE (Exploited)</option>
                      <option value="BLOCKED">BLOCKED (Mitigated)</option>
                    </select>
                  </div>

                  <button
                    onClick={handleRunRca}
                    disabled={rcaLoading}
                    style={{
                      padding: "8px 16px",
                      borderRadius: "6px",
                      background: "var(--accent-primary)",
                      color: "#fff",
                      border: "none",
                      fontSize: "12px",
                      fontWeight: "700",
                      cursor: rcaLoading ? "not-allowed" : "pointer",
                    }}
                  >
                    {rcaLoading ? "Analyzing..." : "🔬 Compute RCA & CVSS"}
                  </button>
                </div>
              </div>

              {!rcaFinding ? (
                <div style={{ padding: "40px 20px", textAlign: "center", color: "var(--text-dim)", background: "var(--bg-surface-elevated)", borderRadius: "8px" }}>
                  Select an evaluation scenario above and click "Compute RCA & CVSS" to analyze root cause and generate code fixes.
                </div>
              ) : (
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
                  {/* Left Column: Root Cause & CVSS v3.1 */}
                  <div style={{ background: "var(--bg-surface-elevated)", border: "1px solid var(--border-subtle)", borderRadius: "8px", padding: "16px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
                      <div>
                        <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--text-muted)" }}>{rcaFinding.finding_id}</div>
                        <h4 style={{ fontSize: "14px", fontWeight: "800", color: "var(--text-main)", margin: "2px 0 0 0" }}>
                          {rcaFinding.title}
                        </h4>
                      </div>

                      {/* CVSS Badge */}
                      <div style={{ textAlign: "right" }}>
                        <div style={{ fontSize: "10px", color: "var(--text-muted)", fontWeight: "600" }}>CVSS v3.1 BASE</div>
                        <div style={{ fontSize: "20px", fontWeight: "900", color: rcaFinding.cvss_severity === "CRITICAL" ? "var(--color-error)" : rcaFinding.cvss_severity === "HIGH" ? "var(--color-claude)" : "var(--color-online)" }}>
                          {rcaFinding.cvss_score.toFixed(1)} <span style={{ fontSize: "11px" }}>{rcaFinding.cvss_severity}</span>
                        </div>
                      </div>
                    </div>

                    {/* CVSS Vector String */}
                    <div style={{ fontSize: "10px", fontFamily: "DM Mono, monospace", background: "var(--bg-primary)", padding: "6px 8px", borderRadius: "4px", color: "var(--accent-cyan)", marginBottom: "14px", wordBreak: "break-all" }}>
                      {rcaFinding.cvss_vector}
                    </div>

                    <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                      <div style={{ background: "var(--bg-primary)", padding: "10px", borderRadius: "6px" }}>
                        <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--text-muted)" }}>ROOT CAUSE CATEGORY</div>
                        <div style={{ fontSize: "12px", color: "var(--text-main)", marginTop: "2px" }}>{rcaFinding.root_cause_category}</div>
                      </div>

                      <div style={{ background: "var(--bg-primary)", padding: "10px", borderRadius: "6px" }}>
                        <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--color-error)" }}>FAILED SECURITY CONTROL</div>
                        <div style={{ fontSize: "12px", color: "var(--text-main)", marginTop: "2px" }}>{rcaFinding.failed_control}</div>
                      </div>

                      <div style={{ background: "var(--bg-primary)", padding: "10px", borderRadius: "6px" }}>
                        <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--color-claude)" }}>TRUST BOUNDARY CROSSED</div>
                        <div style={{ fontSize: "12px", color: "var(--text-main)", marginTop: "2px" }}>{rcaFinding.trust_boundary}</div>
                      </div>

                      <div style={{ fontSize: "11px", color: "var(--text-dim)", marginTop: "4px" }}>
                        {rcaFinding.explanation}
                      </div>
                    </div>
                  </div>

                  {/* Right Column: Automated Remediation Intelligence */}
                  <div style={{ background: "var(--bg-surface-elevated)", border: "1px solid var(--border-subtle)", borderRadius: "8px", padding: "16px" }}>
                    {remediationLoading ? (
                      <div style={{ padding: "40px 20px", textAlign: "center", color: "var(--text-dim)" }}>
                        Generating remediation guidance...
                      </div>
                    ) : !remediationDirective ? (
                      <div style={{ padding: "40px 20px", textAlign: "center", color: "var(--text-dim)" }}>
                        No remediation directive loaded.
                      </div>
                    ) : (
                      <div>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                          <h4 style={{ fontSize: "14px", fontWeight: "800", color: "var(--color-online)", margin: 0 }}>
                            🛡️ Hardening Directive: {remediationDirective.title}
                          </h4>
                        </div>

                        <p style={{ fontSize: "12px", color: "var(--text-muted)", margin: "0 0 10px 0" }}>
                          {remediationDirective.description}
                        </p>

                        <div style={{ marginBottom: "10px" }}>
                          <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--text-muted)", marginBottom: "4px" }}>
                            QUICK MITIGATION
                          </div>
                          <div style={{ fontSize: "12px", color: "var(--text-main)", background: "var(--bg-primary)", padding: "8px", borderRadius: "6px" }}>
                            {remediationDirective.quick_mitigation}
                          </div>
                        </div>

                        {/* Actionable Code Snippet */}
                        {remediationDirective.code_snippets?.length > 0 && (
                          <div>
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
                              <span style={{ fontSize: "11px", fontWeight: "700", color: "var(--accent-cyan)" }}>
                                PYTHON / FASTAPI HARDENING SNIPPET
                              </span>
                              <button
                                onClick={() => handleCopyCode(remediationDirective.code_snippets[0].snippet)}
                                style={{
                                  background: "transparent",
                                  border: "none",
                                  color: copyCodeSuccess ? "var(--color-online)" : "var(--accent-cyan)",
                                  fontSize: "11px",
                                  fontWeight: "600",
                                  cursor: "pointer",
                                }}
                              >
                                {copyCodeSuccess ? "✓ Copied" : "📋 Copy Code"}
                              </button>
                            </div>
                            <pre
                              style={{
                                margin: 0,
                                background: "var(--bg-primary)",
                                border: "1px solid var(--border-subtle)",
                                padding: "10px",
                                borderRadius: "6px",
                                color: "#f8fafc",
                                fontSize: "11px",
                                fontFamily: "DM Mono, monospace",
                                overflowX: "auto",
                                maxHeight: "220px",
                              }}
                            >
                              {remediationDirective.code_snippets[0].snippet}
                            </pre>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}


          {/* TAB 8: Phase E5 Security Regression Intelligence */}
          {activeTab === "regression" && (
            <div>
              {/* Header & Controls Panel */}
              <div
                style={{
                  background: "var(--bg-surface)",
                  borderRadius: "8px",
                  border: "1px solid var(--border-subtle)",
                  padding: "16px",
                  marginBottom: "20px",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <span style={{ fontSize: "16px" }}>🔄</span>
                    <span style={{ fontSize: "14px", fontWeight: "700", color: "var(--text-main)" }}>
                      Security Regression Intelligence Engine
                    </span>
                    <span
                      style={{
                        fontSize: "10px",
                        padding: "2px 8px",
                        borderRadius: "10px",
                        background: "rgba(99,102,241,0.2)",
                        color: "var(--accent-primary)",
                        fontWeight: "700",
                        border: "1px solid rgba(99,102,241,0.4)",
                      }}
                    >
                      PHASE E5
                    </span>
                  </div>
                  <button
                    onClick={handleFetchRegressionHistory}
                    disabled={isFetchingRegressionHistory}
                    style={{
                      padding: "4px 10px",
                      borderRadius: "4px",
                      background: "rgba(255,255,255,0.06)",
                      border: "1px solid var(--border-subtle)",
                      color: "var(--text-muted)",
                      fontSize: "11px",
                      cursor: "pointer",
                    }}
                  >
                    {isFetchingRegressionHistory ? "Refreshing..." : "↻ Refresh History"}
                  </button>
                </div>

                {/* Plan Selection Form */}
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr auto", gap: "12px", alignItems: "end" }}>
                  <div>
                    <label style={{ display: "block", fontSize: "11px", color: "var(--text-dim)", marginBottom: "4px" }}>
                      BASELINE PLAN ID (T₀ / Prior Version):
                    </label>
                    <input
                      type="text"
                      value={regressionBaselinePlanId}
                      onChange={(e) => setRegressionBaselinePlanId(e.target.value)}
                      placeholder="e.g. plan_uuid or paste ID..."
                      style={{
                        width: "100%",
                        padding: "6px 10px",
                        borderRadius: "4px",
                        background: "var(--bg-primary)",
                        border: "1px solid var(--border-subtle)",
                        color: "var(--text-main)",
                        fontSize: "12px",
                        fontFamily: "DM Mono, monospace",
                      }}
                    />
                  </div>
                  <div>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
                      <label style={{ fontSize: "11px", color: "var(--text-dim)" }}>
                        CURRENT PLAN ID (T₁ / Post-Mitigation):
                      </label>
                      {activePlan?.id && (
                        <button
                          onClick={() => setRegressionCurrentPlanId(activePlan.id)}
                          style={{
                            background: "transparent",
                            border: "none",
                            color: "var(--accent-cyan)",
                            fontSize: "10px",
                            cursor: "pointer",
                            padding: 0,
                          }}
                        >
                          Use Active Plan
                        </button>
                      )}
                    </div>
                    <input
                      type="text"
                      value={regressionCurrentPlanId}
                      onChange={(e) => setRegressionCurrentPlanId(e.target.value)}
                      placeholder="e.g. plan_uuid or paste ID..."
                      style={{
                        width: "100%",
                        padding: "6px 10px",
                        borderRadius: "4px",
                        background: "var(--bg-primary)",
                        border: "1px solid var(--border-subtle)",
                        color: "var(--text-main)",
                        fontSize: "12px",
                        fontFamily: "DM Mono, monospace",
                      }}
                    />
                  </div>
                  <button
                    onClick={() => handleRunRegressionComparison()}
                    disabled={isComparingRegression || !regressionBaselinePlanId || !regressionCurrentPlanId}
                    style={{
                      padding: "8px 18px",
                      borderRadius: "6px",
                      background: isComparingRegression ? "var(--bg-card)" : "var(--accent-primary)",
                      color: "#fff",
                      border: "none",
                      fontWeight: "700",
                      fontSize: "12px",
                      cursor: isComparingRegression || !regressionBaselinePlanId || !regressionCurrentPlanId ? "not-allowed" : "pointer",
                      display: "flex",
                      alignItems: "center",
                      gap: "6px",
                      height: "34px",
                    }}
                  >
                    {isComparingRegression ? "Analyzing..." : "⚡ Run Regression Diff"}
                  </button>
                </div>

                {/* Advanced Comparison Flags */}
                <div style={{ display: "flex", gap: "20px", marginTop: "10px", fontSize: "11px", color: "var(--text-dim)" }}>
                  <label style={{ display: "flex", alignItems: "center", gap: "6px", cursor: "pointer" }}>
                    <input
                      type="checkbox"
                      checked={regressionAllowCrossTarget}
                      onChange={(e) => setRegressionAllowCrossTarget(e.target.checked)}
                    />
                    Allow Cross-Target Comparison (Bypass Authority Check)
                  </label>
                  <label style={{ display: "flex", alignItems: "center", gap: "6px", cursor: "pointer" }}>
                    <input
                      type="checkbox"
                      checked={regressionAllowCrossEnv}
                      onChange={(e) => setRegressionAllowCrossEnv(e.target.checked)}
                    />
                    Allow Cross-Environment Comparison (e.g. Staging vs Production)
                  </label>
                </div>
              </div>

              {/* Historical Comparisons Quick-Select */}
              {regressionHistory.length > 0 && (
                <div style={{ marginBottom: "20px" }}>
                  <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--text-dim)", marginBottom: "8px", textTransform: "uppercase" }}>
                    Saved Regression Comparison Runs ({regressionHistory.length})
                  </div>
                  <div style={{ display: "flex", gap: "8px", overflowX: "auto", paddingBottom: "6px" }}>
                    {regressionHistory.map((run) => (
                      <div
                        key={run.comparison_id}
                        onClick={() => handleSelectRegressionComparison(run.comparison_id)}
                        style={{
                          flex: "0 0 auto",
                          padding: "8px 12px",
                          borderRadius: "6px",
                          background: regressionComparison?.comparison_id === run.comparison_id ? "rgba(99,102,241,0.15)" : "var(--bg-surface)",
                          border: `1px solid ${regressionComparison?.comparison_id === run.comparison_id ? "var(--accent-primary)" : "var(--border-subtle)"}`,
                          cursor: "pointer",
                          fontSize: "11px",
                        }}
                      >
                        <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "4px" }}>
                          <span
                            style={{
                              width: "8px",
                              height: "8px",
                              borderRadius: "50%",
                              background: run.regression_verdict === "REGRESSIONS_DETECTED" ? "#ef4444" : run.regression_verdict.startsWith("IMPROVED") ? "#10b981" : "#06b6d4",
                            }}
                          />
                          <span style={{ fontWeight: "700", color: "var(--text-main)" }}>
                            {run.comparison_id}
                          </span>
                        </div>
                        <div style={{ color: "var(--text-muted)", fontSize: "10px" }}>
                          Verdict: <span style={{ fontWeight: "600", color: run.regression_verdict === "REGRESSIONS_DETECTED" ? "#ef4444" : "#10b981" }}>{run.regression_verdict}</span>
                        </div>
                        <div style={{ color: "var(--text-dim)", fontSize: "9px", marginTop: "2px" }}>
                          {new Date(run.created_at).toLocaleString()}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Active Comparison Results View */}
              {regressionComparison ? (
                <div>
                  {/* Verdict & Target Scope Banner */}
                  <div
                    style={{
                      padding: "16px 20px",
                      borderRadius: "8px",
                      background:
                        regressionComparison.regression_verdict === "REGRESSIONS_DETECTED"
                          ? "rgba(239,68,68,0.12)"
                          : regressionComparison.regression_verdict === "REOPENED_VULNERABILITIES_DETECTED"
                          ? "rgba(245,158,11,0.12)"
                          : regressionComparison.regression_verdict === "NEW_VULNERABILITIES_DETECTED"
                          ? "rgba(168,85,247,0.12)"
                          : "rgba(16,185,129,0.12)",
                      border: `1px solid ${
                        regressionComparison.regression_verdict === "REGRESSIONS_DETECTED"
                          ? "rgba(239,68,68,0.3)"
                          : regressionComparison.regression_verdict === "REOPENED_VULNERABILITIES_DETECTED"
                          ? "rgba(245,158,11,0.3)"
                          : regressionComparison.regression_verdict === "NEW_VULNERABILITIES_DETECTED"
                          ? "rgba(168,85,247,0.3)"
                          : "rgba(16,185,129,0.3)"
                      }`,
                      marginBottom: "16px",
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                    }}
                  >
                    <div>
                      <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--text-dim)", textTransform: "uppercase" }}>
                        COMPARISON VERDICT
                      </div>
                      <div
                        style={{
                          fontSize: "18px",
                          fontWeight: "800",
                          color:
                            regressionComparison.regression_verdict === "REGRESSIONS_DETECTED"
                              ? "#ef4444"
                              : regressionComparison.regression_verdict === "REOPENED_VULNERABILITIES_DETECTED"
                              ? "#f59e0b"
                              : regressionComparison.regression_verdict === "NEW_VULNERABILITIES_DETECTED"
                              ? "#a855f7"
                              : "#10b981",
                        }}
                      >
                        {regressionComparison.regression_verdict}
                      </div>
                      <div style={{ fontSize: "12px", color: "var(--text-muted)", marginTop: "4px" }}>
                        Baseline: <code style={{ color: "var(--text-main)" }}>{regressionComparison.baseline_target}</code> ({regressionComparison.baseline_environment || "default"})
                        <span style={{ margin: "0 8px" }}>➔</span>
                        Current: <code style={{ color: "var(--text-main)" }}>{regressionComparison.current_target}</code> ({regressionComparison.current_environment || "default"})
                      </div>
                    </div>
                    <div style={{ textAlign: "right" }}>
                      <div style={{ fontSize: "10px", color: "var(--text-dim)" }}>COMPARISON ID</div>
                      <div style={{ fontFamily: "DM Mono, monospace", fontSize: "12px", color: "var(--text-muted)" }}>
                        {regressionComparison.comparison_id}
                      </div>
                      <div style={{ fontSize: "10px", color: "var(--text-dim)", marginTop: "2px" }}>
                        {new Date(regressionComparison.created_at).toLocaleString()}
                      </div>
                    </div>
                  </div>

                  {/* 5 Executive Delta Cards */}
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: "12px", marginBottom: "16px" }}>
                    <div style={{ background: "var(--bg-surface)", padding: "12px", borderRadius: "8px", border: "1px solid var(--border-subtle)", textAlign: "center" }}>
                      <div style={{ fontSize: "11px", color: "var(--text-dim)", fontWeight: "600" }}>🚨 REGRESSIONS</div>
                      <div style={{ fontSize: "24px", fontWeight: "800", color: regressionComparison.regression_findings_count > 0 ? "#ef4444" : "var(--text-muted)", marginTop: "4px" }}>
                        {regressionComparison.regression_findings_count}
                      </div>
                      <div style={{ fontSize: "10px", color: "var(--text-dim)", marginTop: "2px" }}>Control Degraded</div>
                    </div>

                    <div style={{ background: "var(--bg-surface)", padding: "12px", borderRadius: "8px", border: "1px solid var(--border-subtle)", textAlign: "center" }}>
                      <div style={{ fontSize: "11px", color: "var(--text-dim)", fontWeight: "600" }}>🔁 REOPENED</div>
                      <div style={{ fontSize: "24px", fontWeight: "800", color: regressionComparison.reopened_findings_count > 0 ? "#f59e0b" : "var(--text-muted)", marginTop: "4px" }}>
                        {regressionComparison.reopened_findings_count}
                      </div>
                      <div style={{ fontSize: "10px", color: "var(--text-dim)", marginTop: "2px" }}>Prior Fix Recurred</div>
                    </div>

                    <div style={{ background: "var(--bg-surface)", padding: "12px", borderRadius: "8px", border: "1px solid var(--border-subtle)", textAlign: "center" }}>
                      <div style={{ fontSize: "11px", color: "var(--text-dim)", fontWeight: "600" }}>🆕 NEW FINDINGS</div>
                      <div style={{ fontSize: "24px", fontWeight: "800", color: regressionComparison.new_findings_count > 0 ? "#a855f7" : "var(--text-muted)", marginTop: "4px" }}>
                        {regressionComparison.new_findings_count}
                      </div>
                      <div style={{ fontSize: "10px", color: "var(--text-dim)", marginTop: "2px" }}>Newly Discovered</div>
                    </div>

                    <div style={{ background: "var(--bg-surface)", padding: "12px", borderRadius: "8px", border: "1px solid var(--border-subtle)", textAlign: "center" }}>
                      <div style={{ fontSize: "11px", color: "var(--text-dim)", fontWeight: "600" }}>⏳ PERSISTENT</div>
                      <div style={{ fontSize: "24px", fontWeight: "800", color: regressionComparison.persistent_findings_count > 0 ? "#f97316" : "var(--text-muted)", marginTop: "4px" }}>
                        {regressionComparison.persistent_findings_count}
                      </div>
                      <div style={{ fontSize: "10px", color: "var(--text-dim)", marginTop: "2px" }}>Still Vulnerable</div>
                    </div>

                    <div style={{ background: "var(--bg-surface)", padding: "12px", borderRadius: "8px", border: "1px solid var(--border-subtle)", textAlign: "center" }}>
                      <div style={{ fontSize: "11px", color: "var(--text-dim)", fontWeight: "600" }}>✅ RESOLVED</div>
                      <div style={{ fontSize: "24px", fontWeight: "800", color: regressionComparison.resolved_findings_count > 0 ? "#10b981" : "var(--text-muted)", marginTop: "4px" }}>
                        {regressionComparison.resolved_findings_count}
                      </div>
                      <div style={{ fontSize: "10px", color: "var(--text-dim)", marginTop: "2px" }}>Successfully Fixed</div>
                    </div>
                  </div>

                  {/* Statistical Scores & Population Resilience Panel */}
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: "12px", marginBottom: "16px" }}>
                    <div style={{ background: "var(--bg-card)", padding: "12px", borderRadius: "8px", border: "1px solid var(--border-subtle)" }}>
                      <div style={{ fontSize: "11px", color: "var(--text-dim)" }}>Baseline Overall Score</div>
                      <div style={{ fontSize: "20px", fontWeight: "700", color: "var(--text-main)", marginTop: "4px" }}>
                        {(regressionComparison.baseline_resilience_score * 100).toFixed(1)}%
                      </div>
                    </div>

                    <div style={{ background: "var(--bg-card)", padding: "12px", borderRadius: "8px", border: "1px solid var(--border-subtle)" }}>
                      <div style={{ fontSize: "11px", color: "var(--text-dim)" }}>Current Overall Score</div>
                      <div style={{ fontSize: "20px", fontWeight: "700", color: "var(--text-main)", marginTop: "4px" }}>
                        {(regressionComparison.current_resilience_score * 100).toFixed(1)}%
                      </div>
                    </div>

                    <div style={{ background: "var(--bg-card)", padding: "12px", borderRadius: "8px", border: "1px solid rgba(99,102,241,0.3)" }}>
                      <div style={{ fontSize: "11px", color: "var(--accent-primary)", fontWeight: "700" }}>
                        Intersection Resilience (R_inter)
                      </div>
                      <div style={{ fontSize: "20px", fontWeight: "800", color: "var(--accent-cyan)", marginTop: "4px" }}>
                        {(regressionComparison.intersection_resilience_score * 100).toFixed(1)}%
                      </div>
                      <div style={{ fontSize: "9px", color: "var(--text-dim)", marginTop: "2px" }}>
                        Common Set Control Efficacy
                      </div>
                    </div>

                    <div style={{ background: "var(--bg-card)", padding: "12px", borderRadius: "8px", border: "1px solid var(--border-subtle)" }}>
                      <div style={{ fontSize: "11px", color: "var(--text-dim)" }}>Resilience Drift (ΔR)</div>
                      <div
                        style={{
                          fontSize: "20px",
                          fontWeight: "700",
                          color: regressionComparison.resilience_drift > 0 ? "#10b981" : regressionComparison.resilience_drift < 0 ? "#ef4444" : "var(--text-muted)",
                          marginTop: "4px",
                        }}
                      >
                        {regressionComparison.resilience_drift > 0 ? "+" : ""}
                        {(regressionComparison.resilience_drift * 100).toFixed(1)}%
                      </div>
                    </div>

                    <div style={{ background: "var(--bg-card)", padding: "12px", borderRadius: "8px", border: "1px solid var(--border-subtle)" }}>
                      <div style={{ fontSize: "11px", color: "var(--text-dim)" }}>Surface Expansion Factor</div>
                      <div style={{ fontSize: "20px", fontWeight: "700", color: "var(--text-main)", marginTop: "4px" }}>
                        {regressionComparison.expansion_factor}x
                      </div>
                      <div style={{ fontSize: "9px", color: "var(--text-dim)", marginTop: "2px" }}>
                        |E_curr| / |E_base|
                      </div>
                    </div>
                  </div>

                  {/* Population Discrepancy Warning Banner */}
                  {regressionComparison.population_disclosure?.has_population_discrepancy && (
                    <div
                      style={{
                        padding: "12px 16px",
                        borderRadius: "8px",
                        background: "rgba(245,158,11,0.12)",
                        border: "1px solid rgba(245,158,11,0.4)",
                        marginBottom: "16px",
                        display: "flex",
                        alignItems: "flex-start",
                        gap: "10px",
                      }}
                    >
                      <span style={{ fontSize: "18px" }}>⚠️</span>
                      <div style={{ fontSize: "12px", color: "var(--text-main)" }}>
                        <div style={{ fontWeight: "700", color: "#f59e0b", marginBottom: "2px" }}>
                          POPULATION DISCREPANCY DISCLOSURE
                        </div>
                        <div>{regressionComparison.population_disclosure.warning_message}</div>
                        <div style={{ marginTop: "6px", display: "flex", gap: "16px", fontSize: "11px", color: "var(--text-muted)" }}>
                          <span>Baseline scenarios: <strong>{regressionComparison.population_disclosure.baseline_total_scenarios}</strong></span>
                          <span>Current scenarios: <strong>{regressionComparison.population_disclosure.current_total_scenarios}</strong></span>
                          <span>Intersection common: <strong>{regressionComparison.population_disclosure.intersection_scenarios_count}</strong></span>
                          <span>Omitted from baseline: <strong>{regressionComparison.population_disclosure.baseline_only_count}</strong></span>
                          <span>Newly added in current: <strong>{regressionComparison.population_disclosure.current_only_count}</strong></span>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Finding Deltas Filter & Table */}
                  <div
                    style={{
                      background: "var(--bg-surface)",
                      borderRadius: "8px",
                      border: "1px solid var(--border-subtle)",
                      padding: "16px",
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
                      <div style={{ fontSize: "13px", fontWeight: "700", color: "var(--text-main)" }}>
                        FINDING DELTAS REGISTER ({regressionComparison.finding_deltas?.length || 0})
                      </div>
                      <div style={{ display: "flex", gap: "6px" }}>
                        {[
                          { id: "ALL", label: "All Deltas" },
                          { id: "REGRESSION_DETECTED", label: "Regressions" },
                          { id: "REOPENED_VULNERABILITY", label: "Reopened" },
                          { id: "NEW_VULNERABILITY", label: "New" },
                          { id: "PERSISTENT_VULNERABILITY", label: "Persistent" },
                          { id: "RESOLVED_VULNERABILITY", label: "Resolved" },
                        ].map((btn) => (
                          <button
                            key={btn.id}
                            onClick={() => setRegressionFilter(btn.id)}
                            style={{
                              padding: "4px 8px",
                              borderRadius: "4px",
                              fontSize: "10px",
                              fontWeight: "600",
                              cursor: "pointer",
                              border: "1px solid",
                              background: regressionFilter === btn.id ? "var(--accent-primary)" : "transparent",
                              color: regressionFilter === btn.id ? "#fff" : "var(--text-muted)",
                              borderColor: regressionFilter === btn.id ? "var(--accent-primary)" : "var(--border-subtle)",
                            }}
                          >
                            {btn.label}
                          </button>
                        ))}
                      </div>
                    </div>

                    {/* Table View */}
                    <div style={{ overflowX: "auto" }}>
                      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "11px" }}>
                        <thead>
                          <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.1)", textAlign: "left", color: "var(--text-dim)" }}>
                            <th style={{ padding: "8px 10px" }}>Delta Type</th>
                            <th style={{ padding: "8px 10px" }}>Endpoint</th>
                            <th style={{ padding: "8px 10px" }}>Risk & Category</th>
                            <th style={{ padding: "8px 10px" }}>Baseline ➔ Current</th>
                            <th style={{ padding: "8px 10px" }}>Severity / CVSS</th>
                            <th style={{ padding: "8px 10px" }}>Classification Details</th>
                          </tr>
                        </thead>
                        <tbody>
                          {regressionComparison.finding_deltas
                            ?.filter((d) => regressionFilter === "ALL" || d.delta_type === regressionFilter)
                            .map((delta, idx) => (
                              <tr key={idx} style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                                <td style={{ padding: "8px 10px" }}>
                                  <span
                                    style={{
                                      padding: "2px 8px",
                                      borderRadius: "4px",
                                      fontSize: "10px",
                                      fontWeight: "700",
                                      background:
                                        delta.delta_type === "REGRESSION_DETECTED"
                                          ? "rgba(239,68,68,0.2)"
                                          : delta.delta_type === "REOPENED_VULNERABILITY"
                                          ? "rgba(245,158,11,0.2)"
                                          : delta.delta_type === "NEW_VULNERABILITY"
                                          ? "rgba(168,85,247,0.2)"
                                          : delta.delta_type === "RESOLVED_VULNERABILITY"
                                          ? "rgba(16,185,129,0.2)"
                                          : "rgba(249,115,22,0.2)",
                                      color:
                                        delta.delta_type === "REGRESSION_DETECTED"
                                          ? "#ef4444"
                                          : delta.delta_type === "REOPENED_VULNERABILITY"
                                          ? "#f59e0b"
                                          : delta.delta_type === "NEW_VULNERABILITY"
                                          ? "#a855f7"
                                          : delta.delta_type === "RESOLVED_VULNERABILITY"
                                          ? "#10b981"
                                          : "#f97316",
                                    }}
                                  >
                                    {delta.delta_type}
                                  </span>
                                </td>
                                <td style={{ padding: "8px 10px", fontFamily: "DM Mono, monospace", color: "var(--text-main)" }}>
                                  <span style={{ color: "var(--accent-cyan)", marginRight: "4px" }}>{delta.http_method}</span>
                                  {delta.affected_endpoint}
                                </td>
                                <td style={{ padding: "8px 10px" }}>
                                  <span style={{ fontWeight: "700", color: "var(--accent-primary)" }}>{delta.risk_id}</span>
                                  <span style={{ color: "var(--text-dim)", marginLeft: "4px" }}>({delta.category})</span>
                                </td>
                                <td style={{ padding: "8px 10px" }}>
                                  <span style={{ color: "var(--text-dim)" }}>{delta.baseline_status || "UNTESTED"}</span>
                                  <span style={{ margin: "0 6px", color: "var(--accent-cyan)" }}>➔</span>
                                  <span style={{ fontWeight: "700", color: "var(--text-main)" }}>{delta.current_status}</span>
                                </td>
                                <td style={{ padding: "8px 10px" }}>
                                  <span style={{ fontWeight: "600", color: delta.severity === "CRITICAL" ? "#ef4444" : delta.severity === "HIGH" ? "#f97316" : "#f59e0b" }}>
                                    {delta.severity}
                                  </span>
                                  <span style={{ color: "var(--text-dim)", marginLeft: "4px" }}>({delta.cvss_score})</span>
                                </td>
                                <td style={{ padding: "8px 10px", color: "var(--text-muted)", maxWidth: "300px" }}>
                                  {delta.details}
                                </td>
                              </tr>
                            ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              ) : (
                <div style={{ padding: "60px 20px", textAlign: "center", color: "var(--text-dim)" }}>
                  <div style={{ fontSize: "36px", marginBottom: "12px" }}>🔄</div>
                  <div style={{ fontSize: "15px", fontWeight: "700", color: "var(--text-muted)", marginBottom: "4px" }}>
                    No Regression Analysis Loaded
                  </div>
                  <div style={{ fontSize: "12px" }}>
                    Select a Baseline Plan ID and Current Plan ID above, then click "Run Regression Diff" to evaluate delta classifications, population discrepancy, and control stability.
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB: Enterprise Reporting Engine (Phase E6) */}
          {activeTab === "enterprise_reporting" && (
            <div>
              {/* Header Card */}
              <div
                style={{
                  background: "linear-gradient(135deg, rgba(26,54,93,0.3) 0%, rgba(15,23,42,0.6) 100%)",
                  border: "1px solid rgba(59,130,246,0.3)",
                  borderRadius: "12px",
                  padding: "20px",
                  marginBottom: "20px",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "12px" }}>
                  <div>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
                      <span style={{ fontSize: "22px" }}>📑</span>
                      <h2 style={{ fontSize: "18px", fontWeight: "800", color: "#60a5fa", margin: 0 }}>
                        Enterprise Reporting Engine & Cryptographic Integrity
                      </h2>
                      <span
                        style={{
                          fontSize: "10px",
                          padding: "2px 8px",
                          borderRadius: "10px",
                          background: "rgba(59,130,246,0.2)",
                          color: "#60a5fa",
                          border: "1px solid rgba(59,130,246,0.4)",
                          fontWeight: "700",
                        }}
                      >
                        PHASE E6 · MULTI-FORMAT COMPLIANCE
                      </span>
                    </div>
                    <p style={{ fontSize: "12px", color: "var(--text-muted)", margin: 0, maxWidth: "700px" }}>
                      Generates standardized 10-section enterprise security reports in PDF, Excel, CSV, and canonical JSON formats.
                      Sealed with SHA-256 content digests and HMAC-SHA256 authenticity signatures. Archival immutability guaranteed via safe zero-cascade persistence.
                    </p>
                  </div>
                  <button
                    onClick={handleFetchEnterpriseReports}
                    disabled={isFetchingEnterpriseReports}
                    style={{
                      padding: "8px 14px",
                      background: "rgba(255,255,255,0.05)",
                      border: "1px solid rgba(255,255,255,0.1)",
                      borderRadius: "6px",
                      color: "var(--text-main)",
                      fontSize: "12px",
                      fontWeight: "600",
                      cursor: "pointer",
                      display: "flex",
                      alignItems: "center",
                      gap: "6px",
                    }}
                  >
                    🔄 Refresh History
                  </button>
                </div>
              </div>

              {/* Controls Grid */}
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
                  gap: "16px",
                  marginBottom: "20px",
                }}
              >
                {/* Generation Parameters Card */}
                <div
                  style={{
                    background: "var(--bg-surface)",
                    border: "1px solid var(--border-subtle)",
                    borderRadius: "10px",
                    padding: "16px",
                  }}
                >
                  <h3 style={{ fontSize: "13px", fontWeight: "700", color: "var(--text-main)", marginBottom: "12px" }}>
                    ⚙️ Generate Enterprise Report
                  </h3>
                  <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                    <div>
                      <label style={{ fontSize: "11px", fontWeight: "600", color: "var(--text-muted)", display: "block", marginBottom: "4px" }}>
                        Report Type:
                      </label>
                      <select
                        value={reportTypeSelection}
                        onChange={(e) => setReportTypeSelection(e.target.value)}
                        style={{
                          width: "100%",
                          padding: "8px",
                          borderRadius: "6px",
                          background: "var(--bg-surface-elevated)",
                          border: "1px solid var(--border-subtle)",
                          color: "var(--text-main)",
                          fontSize: "12px",
                        }}
                      >
                        <option value="FULL_TECHNICAL">Full Technical Assessment (10 Sections)</option>
                        <option value="EXECUTIVE">Executive Summary & Scorecard</option>
                        <option value="COMPLIANCE">Regulatory Compliance Audit</option>
                      </select>
                    </div>

                    <div>
                      <label style={{ fontSize: "11px", fontWeight: "600", color: "var(--text-muted)", display: "block", marginBottom: "4px" }}>
                        Lead Auditor Name:
                      </label>
                      <input
                        type="text"
                        value={reportLeadAuditor}
                        onChange={(e) => setReportLeadAuditor(e.target.value)}
                        placeholder="ApexShield Security Engine"
                        style={{
                          width: "100%",
                          padding: "8px",
                          borderRadius: "6px",
                          background: "var(--bg-surface-elevated)",
                          border: "1px solid var(--border-subtle)",
                          color: "var(--text-main)",
                          fontSize: "12px",
                        }}
                      />
                    </div>

                    <div>
                      <label style={{ fontSize: "11px", fontWeight: "600", color: "var(--text-muted)", display: "block", marginBottom: "4px" }}>
                        Session ID (Optional):
                      </label>
                      <input
                        type="text"
                        value={reportSessionIdInput}
                        onChange={(e) => setReportSessionIdInput(e.target.value)}
                        placeholder="e.g. audit_session_123"
                        style={{
                          width: "100%",
                          padding: "8px",
                          borderRadius: "6px",
                          background: "var(--bg-surface-elevated)",
                          border: "1px solid var(--border-subtle)",
                          color: "var(--text-main)",
                          fontSize: "12px",
                        }}
                      />
                    </div>

                    <div>
                      <label style={{ fontSize: "11px", fontWeight: "600", color: "var(--text-muted)", display: "block", marginBottom: "4px" }}>
                        Target Export Formats:
                      </label>
                      <div style={{ display: "flex", gap: "12px", flexWrap: "wrap", fontSize: "12px" }}>
                        <label style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                          <input type="checkbox" checked={reportFormatPdf} onChange={(e) => setReportFormatPdf(e.target.checked)} /> PDF
                        </label>
                        <label style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                          <input type="checkbox" checked={reportFormatXlsx} onChange={(e) => setReportFormatXlsx(e.target.checked)} /> XLSX
                        </label>
                        <label style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                          <input type="checkbox" checked={reportFormatCsv} onChange={(e) => setReportFormatCsv(e.target.checked)} /> CSV
                        </label>
                        <label style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                          <input type="checkbox" checked={reportFormatJson} onChange={(e) => setReportFormatJson(e.target.checked)} /> JSON
                        </label>
                      </div>
                    </div>

                    <button
                      onClick={handleGenerateEnterpriseReport}
                      disabled={isGeneratingEnterpriseReport}
                      style={{
                        padding: "10px",
                        borderRadius: "6px",
                        background: "linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%)",
                        border: "none",
                        color: "white",
                        fontSize: "12px",
                        fontWeight: "700",
                        cursor: "pointer",
                        marginTop: "8px",
                      }}
                    >
                      {isGeneratingEnterpriseReport ? "Generating Document..." : "🚀 Generate & Cryptographically Sign Report"}
                    </button>
                  </div>
                </div>

                {/* Historical Reports Archive Card */}
                <div
                  style={{
                    background: "var(--bg-surface)",
                    border: "1px solid var(--border-subtle)",
                    borderRadius: "10px",
                    padding: "16px",
                    maxHeight: "380px",
                    overflowY: "auto",
                  }}
                >
                  <h3 style={{ fontSize: "13px", fontWeight: "700", color: "var(--text-main)", marginBottom: "12px" }}>
                    📚 Historical Reports Archive ({enterpriseReportsList.length})
                  </h3>
                  {enterpriseReportsList.length === 0 ? (
                    <div style={{ color: "var(--text-dim)", fontSize: "12px", textAlign: "center", padding: "30px 10px" }}>
                      No reports generated yet. Click "Generate Report" to compile your first enterprise report.
                    </div>
                  ) : (
                    <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                      {enterpriseReportsList.map((rpt) => (
                        <div
                          key={rpt.report_id}
                          onClick={() => handleLoadEnterpriseReportDetail(rpt.report_id)}
                          style={{
                            padding: "10px",
                            borderRadius: "6px",
                            background: selectedEnterpriseReport?.summary?.report_id === rpt.report_id ? "rgba(59,130,246,0.15)" : "var(--bg-surface-elevated)",
                            border: selectedEnterpriseReport?.summary?.report_id === rpt.report_id ? "1px solid #3b82f6" : "1px solid var(--border-subtle)",
                            cursor: "pointer",
                          }}
                        >
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                            <span style={{ fontWeight: "700", fontSize: "12px", color: "var(--text-main)" }}>{rpt.report_id}</span>
                            <span style={{ fontSize: "11px", fontWeight: "700", color: rpt.resilience_score >= 0.8 ? "#10b981" : "#ef4444" }}>
                              {Math.round(rpt.resilience_score * 100)}% Resilience
                            </span>
                          </div>
                          <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "4px" }}>
                            {rpt.target_scope} • {rpt.total_findings_count} finding(s) • {new Date(rpt.created_at).toLocaleDateString()}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              {/* Active Report Detail View */}
              {selectedEnterpriseReport ? (
                <div>
                  {/* Cryptographic Verification Seal Card */}
                  <div
                    style={{
                      background: "var(--bg-surface-elevated)",
                      border: "1px solid var(--border-subtle)",
                      borderRadius: "10px",
                      padding: "16px",
                      marginBottom: "20px",
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "10px" }}>
                      <div>
                        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                          <span style={{ fontSize: "18px" }}>🔐</span>
                          <span style={{ fontWeight: "800", fontSize: "14px", color: "var(--text-main)" }}>
                            Cryptographic Integrity & Authenticity Manifest
                          </span>
                          <span
                            style={{
                              padding: "2px 8px",
                              borderRadius: "10px",
                              fontSize: "10px",
                              fontWeight: "700",
                              background: "rgba(16,185,129,0.2)",
                              color: "#10b981",
                            }}
                          >
                            SEALED & SIGNED
                          </span>
                        </div>
                        <div style={{ fontSize: "11px", fontFamily: "DM Mono, monospace", color: "var(--text-muted)", marginTop: "6px" }}>
                          <b>SHA-256 Digest:</b> {selectedEnterpriseReport.summary.report_hash}
                        </div>
                        <div style={{ fontSize: "11px", fontFamily: "DM Mono, monospace", color: "var(--text-muted)", marginTop: "2px" }}>
                          <b>HMAC-SHA256 Token:</b> {selectedEnterpriseReport.summary.hmac_signature} (Key: {selectedEnterpriseReport.summary.signing_key_id})
                        </div>
                      </div>

                      <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                        <button
                          onClick={() => handleVerifyEnterpriseReport(selectedEnterpriseReport.summary.report_id)}
                          disabled={isVerifyingEnterpriseReport}
                          style={{
                            padding: "8px 14px",
                            background: "rgba(16,185,129,0.15)",
                            border: "1px solid #10b981",
                            borderRadius: "6px",
                            color: "#10b981",
                            fontSize: "12px",
                            fontWeight: "700",
                            cursor: "pointer",
                          }}
                        >
                          {isVerifyingEnterpriseReport ? "Verifying..." : "🛡️ Verify Authenticity"}
                        </button>
                      </div>
                    </div>

                    {reportVerificationResult && (
                      <div
                        style={{
                          marginTop: "12px",
                          padding: "10px",
                          borderRadius: "6px",
                          background: reportVerificationResult.is_valid ? "rgba(16,185,129,0.1)" : "rgba(239,68,68,0.1)",
                          border: `1px solid ${reportVerificationResult.is_valid ? "#10b981" : "#ef4444"}`,
                          fontSize: "12px",
                          color: reportVerificationResult.is_valid ? "#10b981" : "#ef4444",
                          fontWeight: "600",
                        }}
                      >
                        Verification Status: {reportVerificationResult.status} • Content Integrity: {reportVerificationResult.content_integrity_verified ? "PASSED" : "FAILED"} • Source Authenticity: {reportVerificationResult.source_authenticity_verified ? "PASSED" : "FAILED"}
                      </div>
                    )}

                    {/* Download Buttons Bar */}
                    <div style={{ display: "flex", gap: "10px", marginTop: "14px", flexWrap: "wrap" }}>
                      {selectedEnterpriseReport.summary.has_pdf && (
                        <a
                          href={`${API_BASE}${selectedEnterpriseReport.download_urls.pdf}`}
                          target="_blank"
                          rel="noreferrer"
                          style={{
                            padding: "6px 12px",
                            borderRadius: "6px",
                            background: "rgba(239,68,68,0.2)",
                            border: "1px solid #ef4444",
                            color: "#ef4444",
                            fontSize: "11px",
                            fontWeight: "700",
                            textDecoration: "none",
                            display: "flex",
                            alignItems: "center",
                            gap: "4px",
                          }}
                        >
                          📄 Download PDF
                        </a>
                      )}
                      {selectedEnterpriseReport.summary.has_excel && (
                        <a
                          href={`${API_BASE}${selectedEnterpriseReport.download_urls.xlsx}`}
                          target="_blank"
                          rel="noreferrer"
                          style={{
                            padding: "6px 12px",
                            borderRadius: "6px",
                            background: "rgba(16,185,129,0.2)",
                            border: "1px solid #10b981",
                            color: "#10b981",
                            fontSize: "11px",
                            fontWeight: "700",
                            textDecoration: "none",
                            display: "flex",
                            alignItems: "center",
                            gap: "4px",
                          }}
                        >
                          📊 Download Excel (XLSX)
                        </a>
                      )}
                      {selectedEnterpriseReport.summary.has_csv && (
                        <a
                          href={`${API_BASE}${selectedEnterpriseReport.download_urls.csv}`}
                          target="_blank"
                          rel="noreferrer"
                          style={{
                            padding: "6px 12px",
                            borderRadius: "6px",
                            background: "rgba(245,158,11,0.2)",
                            border: "1px solid #f59e0b",
                            color: "#f59e0b",
                            fontSize: "11px",
                            fontWeight: "700",
                            textDecoration: "none",
                            display: "flex",
                            alignItems: "center",
                            gap: "4px",
                          }}
                        >
                          📋 Download CSV
                        </a>
                      )}
                      {selectedEnterpriseReport.summary.has_json && (
                        <a
                          href={`${API_BASE}${selectedEnterpriseReport.download_urls.json}`}
                          target="_blank"
                          rel="noreferrer"
                          style={{
                            padding: "6px 12px",
                            borderRadius: "6px",
                            background: "rgba(168,85,247,0.2)",
                            border: "1px solid #a855f7",
                            color: "#a855f7",
                            fontSize: "11px",
                            fontWeight: "700",
                            textDecoration: "none",
                            display: "flex",
                            alignItems: "center",
                            gap: "4px",
                          }}
                        >
                          📦 Download JSON
                        </a>
                      )}
                    </div>
                  </div>

                  {/* 10-Section Tab Selector */}
                  <div style={{ display: "flex", gap: "6px", flexWrap: "wrap", marginBottom: "16px" }}>
                    {[
                      { id: "s1", label: "1. Exec Summary" },
                      { id: "s2", label: "2. Scope" },
                      { id: "s3", label: "3. OWASP Matrix" },
                      { id: "s4", label: "4. Attack Chain" },
                      { id: "s5", label: "5. Findings" },
                      { id: "s6", label: "6. Evidence" },
                      { id: "s7", label: "7. RCA & CVSS" },
                      { id: "s8", label: "8. Remediation" },
                      { id: "s9", label: "9. Regression" },
                      { id: "s10", label: "10. Signatures" },
                    ].map((sec) => (
                      <button
                        key={sec.id}
                        onClick={() => setReportActiveSection(sec.id)}
                        style={{
                          padding: "6px 10px",
                          borderRadius: "4px",
                          background: reportActiveSection === sec.id ? "var(--accent-cyan)" : "var(--bg-surface-elevated)",
                          color: reportActiveSection === sec.id ? "#000" : "var(--text-muted)",
                          border: "none",
                          fontSize: "11px",
                          fontWeight: "700",
                          cursor: "pointer",
                        }}
                      >
                        {sec.label}
                      </button>
                    ))}
                  </div>

                  {/* Section Contents */}
                  <div style={{ background: "var(--bg-surface)", border: "1px solid var(--border-subtle)", borderRadius: "10px", padding: "16px" }}>
                    {reportActiveSection === "s1" && (
                      <div>
                        <h4 style={{ fontSize: "14px", fontWeight: "700", color: "var(--text-main)", marginBottom: "8px" }}>
                          Executive Summary
                        </h4>
                        <p style={{ fontSize: "12px", color: "var(--text-muted)", lineHeight: "1.5" }}>
                          {selectedEnterpriseReport.report_data.section_1_executive_summary?.executive_brief}
                        </p>
                      </div>
                    )}
                    {reportActiveSection === "s2" && (
                      <div>
                        <h4 style={{ fontSize: "14px", fontWeight: "700", color: "var(--text-main)", marginBottom: "8px" }}>
                          Technical Scope
                        </h4>
                        <pre style={{ fontSize: "11px", background: "var(--bg-surface-elevated)", padding: "12px", borderRadius: "6px", color: "var(--text-main)", overflowX: "auto" }}>
                          {JSON.stringify(selectedEnterpriseReport.report_data.section_2_technical_scope, null, 2)}
                        </pre>
                      </div>
                    )}
                    {reportActiveSection === "s3" && (
                      <div>
                        <h4 style={{ fontSize: "14px", fontWeight: "700", color: "var(--text-main)", marginBottom: "8px" }}>
                          OWASP Top 10 Coverage Matrix (20 Categories)
                        </h4>
                        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "8px" }}>
                          {selectedEnterpriseReport.report_data.section_3_owasp_coverage_matrix?.matrix?.map((row, idx) => (
                            <div key={idx} style={{ padding: "8px", background: "var(--bg-surface-elevated)", borderRadius: "6px", fontSize: "11px" }}>
                              <span style={{ fontWeight: "700", color: "var(--accent-primary)" }}>{row.risk_id}</span> • {row.risk_name}
                              <div style={{ color: row.findings_count > 0 ? "#ef4444" : "#10b981", fontWeight: "600", marginTop: "2px" }}>
                                {row.coverage_status} ({row.findings_count} findings)
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    {reportActiveSection === "s5" && (
                      <div>
                        <h4 style={{ fontSize: "14px", fontWeight: "700", color: "var(--text-main)", marginBottom: "8px" }}>
                          Vulnerability Findings Register ({selectedEnterpriseReport.report_data.section_5_vulnerability_findings?.findings_count || 0})
                        </h4>
                        <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                          {selectedEnterpriseReport.report_data.section_5_vulnerability_findings?.findings?.map((f, idx) => (
                            <div key={idx} style={{ padding: "10px", background: "var(--bg-surface-elevated)", borderRadius: "6px", fontSize: "12px" }}>
                              <div style={{ display: "flex", justifyContent: "space-between" }}>
                                <span style={{ fontWeight: "700", color: "var(--text-main)" }}>{f.finding_id}: {f.title}</span>
                                <span style={{ fontWeight: "700", color: f.severity === "CRITICAL" ? "#ef4444" : f.severity === "HIGH" ? "#f97316" : "#f59e0b" }}>{f.severity} (CVSS: {f.cvss_score})</span>
                              </div>
                              <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "4px" }}>
                                Endpoint: <code>{f.http_method} {f.affected_endpoint}</code> • Status: <b>{f.lifecycle_status}</b>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    {reportActiveSection === "s6" && (
                      <div>
                        <h4 style={{ fontSize: "14px", fontWeight: "700", color: "var(--text-main)", marginBottom: "8px" }}>
                          Evidence & Execution Trace Ledger
                        </h4>
                        <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                          {selectedEnterpriseReport.report_data.section_6_evidence_trace_ledger?.traces?.map((tr, idx) => (
                            <div key={idx} style={{ padding: "8px", background: "var(--bg-surface-elevated)", borderRadius: "6px", fontSize: "11px", fontFamily: "DM Mono, monospace" }}>
                              <div><b>Finding:</b> {tr.finding_id} • <b>Status:</b> {tr.evidence_status}</div>
                              <div style={{ color: "var(--text-dim)", marginTop: "2px" }}>Digest: {tr.evidence_digest}</div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    {reportActiveSection === "s8" && (
                      <div>
                        <h4 style={{ fontSize: "14px", fontWeight: "700", color: "var(--text-main)", marginBottom: "8px" }}>
                          Remediation Roadmap
                        </h4>
                        <pre style={{ fontSize: "11px", background: "var(--bg-surface-elevated)", padding: "12px", borderRadius: "6px", color: "var(--text-main)", overflowX: "auto" }}>
                          {JSON.stringify(selectedEnterpriseReport.report_data.section_8_remediation_roadmap, null, 2)}
                        </pre>
                      </div>
                    )}
                    {reportActiveSection === "s10" && (
                      <div>
                        <h4 style={{ fontSize: "14px", fontWeight: "700", color: "var(--text-main)", marginBottom: "8px" }}>
                          Residual Risk & Signatures
                        </h4>
                        <pre style={{ fontSize: "11px", background: "var(--bg-surface-elevated)", padding: "12px", borderRadius: "6px", color: "var(--text-main)", overflowX: "auto" }}>
                          {JSON.stringify(selectedEnterpriseReport.report_data.section_10_residual_risk_and_signatures, null, 2)}
                        </pre>
                      </div>
                    )}
                    {!["s1", "s2", "s3", "s5", "s6", "s8", "s10"].includes(reportActiveSection) && (
                      <div>
                        <h4 style={{ fontSize: "14px", fontWeight: "700", color: "var(--text-main)", marginBottom: "8px" }}>
                          Section Details
                        </h4>
                        <pre style={{ fontSize: "11px", background: "var(--bg-surface-elevated)", padding: "12px", borderRadius: "6px", color: "var(--text-main)", overflowX: "auto" }}>
                          {JSON.stringify(selectedEnterpriseReport.report_data[`section_${reportActiveSection.slice(1)}_...`] || selectedEnterpriseReport.report_data, null, 2)}
                        </pre>
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div style={{ padding: "60px 20px", textAlign: "center", color: "var(--text-dim)" }}>
                  <div style={{ fontSize: "36px", marginBottom: "12px" }}>📑</div>
                  <div style={{ fontSize: "15px", fontWeight: "700", color: "var(--text-muted)", marginBottom: "4px" }}>
                    No Enterprise Report Selected
                  </div>
                  <div style={{ fontSize: "12px" }}>
                    Select an archived report from the list on the right, or click "Generate & Cryptographically Sign Report" to create a new compliance artifact.
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB: Decision Explainability (Phase E7) */}
          {activeTab === "explainability" && (
            <div>
              {/* Header Controls Bar */}
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px", padding: "16px", background: "var(--bg-surface)", border: "1px solid var(--border-subtle)", borderRadius: "10px" }}>
                <div>
                  <h3 style={{ fontSize: "16px", fontWeight: "700", color: "var(--text-main)", marginBottom: "4px" }}>
                    🧠 Explainable Security Decision Engine
                  </h3>
                  <p style={{ fontSize: "12px", color: "var(--text-muted)", margin: 0 }}>
                    Auditable decision traces, deterministic rationales, rejected alternatives, and pre-storage redacted contexts.
                  </p>
                </div>
                <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
                  <select
                    value={decisionFilterType}
                    onChange={(e) => {
                      setDecisionFilterType(e.target.value);
                      handleFetchDecisions(e.target.value);
                    }}
                    style={{
                      background: "var(--bg-surface-elevated)",
                      color: "var(--text-main)",
                      border: "1px solid var(--border-subtle)",
                      borderRadius: "6px",
                      padding: "8px 12px",
                      fontSize: "12px",
                      fontWeight: "600",
                    }}
                  >
                    <option value="">All Decision Types (7)</option>
                    <option value="RISK_SELECTION">RISK_SELECTION</option>
                    <option value="TEST_PLANNING">TEST_PLANNING</option>
                    <option value="PAYLOAD_MUTATION">PAYLOAD_MUTATION</option>
                    <option value="CHAIN_TERMINATION">CHAIN_TERMINATION</option>
                    <option value="VERDICT_CLASSIFICATION">VERDICT_CLASSIFICATION</option>
                    <option value="SEVERITY_SCORING">SEVERITY_SCORING</option>
                    <option value="REMEDIATION_DIRECTIVE">REMEDIATION_DIRECTIVE</option>
                  </select>
                  <button
                    onClick={() => handleFetchDecisions()}
                    disabled={isFetchingDecisions}
                    style={{
                      padding: "8px 14px",
                      background: "var(--accent-primary)",
                      color: "#fff",
                      border: "none",
                      borderRadius: "6px",
                      fontSize: "12px",
                      fontWeight: "600",
                      cursor: "pointer",
                      display: "flex",
                      alignItems: "center",
                      gap: "6px",
                    }}
                  >
                    {isFetchingDecisions ? "Refreshing..." : "🔄 Refresh Log"}
                  </button>
                </div>
              </div>

              {/* Main Content: Left List / Right Inspector */}
              <div style={{ display: "grid", gridTemplateColumns: "380px 1fr", gap: "20px", alignItems: "start" }}>
                {/* Left: Decisions Timeline List */}
                <div style={{ background: "var(--bg-surface)", border: "1px solid var(--border-subtle)", borderRadius: "10px", padding: "16px", maxHeight: "750px", overflowY: "auto" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
                    <span style={{ fontSize: "13px", fontWeight: "700", color: "var(--text-main)" }}>
                      Audit Log Traces
                    </span>
                    <span style={{ fontSize: "11px", padding: "2px 8px", borderRadius: "10px", background: "rgba(99,102,241,0.2)", color: "var(--accent-primary)", fontWeight: "700" }}>
                      {decisionsList.length} Records
                    </span>
                  </div>

                  {decisionsList.length === 0 ? (
                    <div style={{ padding: "40px 10px", textAlign: "center", color: "var(--text-dim)", fontSize: "12px" }}>
                      No decisions recorded yet. Run a security test plan to capture explainable traces.
                    </div>
                  ) : (
                    <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                      {decisionsList.map((d) => {
                        const isSelected = selectedDecision && selectedDecision.decision_id === d.decision_id;
                        const conf = Number(d.confidence || 0);
                        const confColor = conf >= 0.8 ? "#10b981" : conf >= 0.5 ? "#f59e0b" : "#ef4444";
                        return (
                          <div
                            key={d.decision_id}
                            onClick={() => setSelectedDecision(d)}
                            style={{
                              padding: "12px",
                              borderRadius: "8px",
                              background: isSelected ? "rgba(99,102,241,0.15)" : "var(--bg-surface-elevated)",
                              border: isSelected ? "1px solid var(--accent-primary)" : "1px solid var(--border-subtle)",
                              cursor: "pointer",
                              transition: "all 0.15s ease",
                            }}
                          >
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
                              <span style={{ fontSize: "11px", fontWeight: "700", color: "var(--accent-cyan)", letterSpacing: "0.3px" }}>
                                {d.decision_type}
                              </span>
                              <span style={{ fontSize: "10px", fontWeight: "700", padding: "1px 6px", borderRadius: "8px", background: `${confColor}22`, color: confColor }}>
                                Conf: {(conf * 100).toFixed(0)}%
                              </span>
                            </div>
                            <div style={{ fontSize: "12px", fontWeight: "600", color: "var(--text-main)", marginBottom: "4px", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                              {d.selected_action}
                            </div>
                            <div style={{ display: "flex", justifyContent: "space-between", fontSize: "10px", color: "var(--text-muted)" }}>
                              <span>{d.decision_id}</span>
                              <span>{d.decision_timestamp ? new Date(d.decision_timestamp).toLocaleTimeString() : ""}</span>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>

                {/* Right: Detailed Decision Inspector */}
                {selectedDecision ? (
                  <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
                    {/* Header Card */}
                    <div style={{ background: "var(--bg-surface)", border: "1px solid var(--border-subtle)", borderRadius: "10px", padding: "16px" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "12px" }}>
                        <div>
                          <div style={{ display: "flex", gap: "8px", alignItems: "center", marginBottom: "4px" }}>
                            <span style={{ fontSize: "11px", padding: "2px 8px", borderRadius: "12px", background: "rgba(99,102,241,0.2)", color: "var(--accent-primary)", fontWeight: "700" }}>
                              {selectedDecision.decision_type}
                            </span>
                            <span style={{ fontSize: "11px", color: "var(--text-dim)" }}>
                              {selectedDecision.decision_id}
                            </span>
                          </div>
                          <h4 style={{ fontSize: "15px", fontWeight: "700", color: "var(--text-main)", margin: 0 }}>
                            {selectedDecision.selected_action}
                          </h4>
                        </div>
                        <div style={{ textAlign: "right" }}>
                          <div style={{ fontSize: "10px", color: "var(--text-muted)", marginBottom: "2px" }}>CALCULATED CONFIDENCE</div>
                          <div style={{ fontSize: "16px", fontWeight: "800", color: Number(selectedDecision.confidence) >= 0.8 ? "#10b981" : Number(selectedDecision.confidence) >= 0.5 ? "#f59e0b" : "#ef4444" }}>
                            {(Number(selectedDecision.confidence) * 100).toFixed(0)}%
                          </div>
                        </div>
                      </div>

                      {/* Deterministic Reasoning Summary */}
                      <div style={{ padding: "12px", background: "var(--bg-surface-elevated)", borderRadius: "8px", borderLeft: "3px solid var(--accent-primary)", marginBottom: "12px" }}>
                        <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--accent-primary)", marginBottom: "4px" }}>
                          DETERMINISTIC RULE-BASED RATIONALE
                        </div>
                        <p style={{ fontSize: "12px", color: "var(--text-main)", margin: 0, lineHeight: "1.5" }}>
                          {selectedDecision.reasoning_summary || selectedDecision.decision_reason}
                        </p>
                      </div>

                      {/* Metadata Badges */}
                      <div style={{ display: "flex", flexWrap: "wrap", gap: "8px", fontSize: "11px" }}>
                        <span style={{ padding: "4px 8px", background: "var(--bg-surface-elevated)", borderRadius: "6px", color: "var(--text-muted)" }}>
                          Session: <strong style={{ color: "var(--text-main)" }}>{selectedDecision.session_id || "Unlinked"}</strong>
                        </span>
                        <span style={{ padding: "4px 8px", background: "var(--bg-surface-elevated)", borderRadius: "6px", color: "var(--text-muted)" }}>
                          Finding: <strong style={{ color: "var(--text-main)" }}>{selectedDecision.finding_id || "None"}</strong>
                        </span>
                        <span style={{ padding: "4px 8px", background: "var(--bg-surface-elevated)", borderRadius: "6px", color: "var(--text-muted)" }}>
                          Provenance: <strong style={{ color: "var(--text-main)" }}>{selectedDecision.provenance || "ExplainabilityEngine_v1"}</strong>
                        </span>
                      </div>
                    </div>

                    {/* Alternatives Evaluated & Rejection Reasons Table */}
                    <div style={{ background: "var(--bg-surface)", border: "1px solid var(--border-subtle)", borderRadius: "10px", padding: "16px" }}>
                      <h4 style={{ fontSize: "13px", fontWeight: "700", color: "var(--text-main)", marginBottom: "12px" }}>
                        Alternatives Considered & Explicit Rejection Reasons
                      </h4>
                      {(!selectedDecision.alternatives_considered || selectedDecision.alternatives_considered.length === 0) ? (
                        <div style={{ fontSize: "12px", color: "var(--text-dim)", fontStyle: "italic" }}>
                          No alternative actions were viable under the active scope and security constraints.
                        </div>
                      ) : (
                        <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                          {selectedDecision.alternatives_considered.map((alt, idx) => {
                            const reason = selectedDecision.rejection_reasons?.[alt] || "Discarded due to lower heuristic score or policy constraint.";
                            return (
                              <div key={idx} style={{ padding: "10px", background: "var(--bg-surface-elevated)", borderRadius: "6px", fontSize: "12px" }}>
                                <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "4px" }}>
                                  <span style={{ color: "#ef4444", fontWeight: "700" }}>✕ Rejected:</span>
                                  <span style={{ fontWeight: "600", color: "var(--text-main)" }}>{alt}</span>
                                </div>
                                <div style={{ fontSize: "11px", color: "var(--text-muted)", paddingLeft: "18px" }}>
                                  <strong>Reason:</strong> {reason}
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>

                    {/* Supporting Evidence References */}
                    <div style={{ background: "var(--bg-surface)", border: "1px solid var(--border-subtle)", borderRadius: "10px", padding: "16px" }}>
                      <h4 style={{ fontSize: "13px", fontWeight: "700", color: "var(--text-main)", marginBottom: "10px" }}>
                        Cryptographic Evidence References
                      </h4>
                      {(!selectedDecision.evidence_references || selectedDecision.evidence_references.length === 0) ? (
                        <div style={{ fontSize: "12px", color: "var(--text-dim)", fontStyle: "italic" }}>
                          No direct HTTP wire records referenced (Exploratory / Initial Planning Decision).
                        </div>
                      ) : (
                        <div style={{ display: "flex", flexWrap: "wrap", gap: "8px" }}>
                          {selectedDecision.evidence_references.map((ev, idx) => (
                            <span key={idx} style={{ padding: "4px 8px", background: "rgba(16,185,129,0.15)", border: "1px solid rgba(16,185,129,0.3)", borderRadius: "6px", fontSize: "11px", color: "#10b981", fontFamily: "monospace" }}>
                              🔒 {ev}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Pre-Storage Redacted Input Context */}
                    <div style={{ background: "var(--bg-surface)", border: "1px solid var(--border-subtle)", borderRadius: "10px", padding: "16px" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "10px" }}>
                        <h4 style={{ fontSize: "13px", fontWeight: "700", color: "var(--text-main)", margin: 0 }}>
                          Redacted Observable Context
                        </h4>
                        <span style={{ fontSize: "10px", padding: "2px 6px", borderRadius: "6px", background: "rgba(16,185,129,0.15)", color: "#10b981", fontWeight: "700" }}>
                          ✓ Secrets & Tokens Scrubbed
                        </span>
                      </div>
                      <pre style={{ fontSize: "11px", background: "var(--bg-surface-elevated)", padding: "12px", borderRadius: "6px", color: "var(--text-main)", overflowX: "auto", margin: 0 }}>
                        {JSON.stringify(selectedDecision.input_context || {}, null, 2)}
                      </pre>
                    </div>

                    {/* Active Safety Constraints Enforced */}
                    <div style={{ background: "var(--bg-surface)", border: "1px solid var(--border-subtle)", borderRadius: "10px", padding: "16px" }}>
                      <h4 style={{ fontSize: "13px", fontWeight: "700", color: "var(--text-main)", marginBottom: "10px" }}>
                        Active Safety Boundaries Enforced
                      </h4>
                      <pre style={{ fontSize: "11px", background: "var(--bg-surface-elevated)", padding: "12px", borderRadius: "6px", color: "var(--text-main)", overflowX: "auto", margin: 0 }}>
                        {JSON.stringify(selectedDecision.safety_constraints || { loopback_only: true, max_requests: 15, timeout_sec: 8.0 }, null, 2)}
                      </pre>
                    </div>
                  </div>
                ) : (
                  <div style={{ padding: "60px 20px", textAlign: "center", color: "var(--text-dim)", background: "var(--bg-surface)", borderRadius: "10px", border: "1px solid var(--border-subtle)" }}>
                    <div style={{ fontSize: "36px", marginBottom: "12px" }}>🧠</div>
                    <div style={{ fontSize: "15px", fontWeight: "700", color: "var(--text-muted)", marginBottom: "4px" }}>
                      No Decision Trace Selected
                    </div>
                    <div style={{ fontSize: "12px" }}>
                      Select a decision from the left panel to inspect its deterministic rationale, alternatives evaluated, and credential-redacted context.
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB: Claude Code Configuration Security Assessment */}
          {activeTab === "claude_code" && (
            <div id="claude-code-assessment-view" data-testid="claude-code-assessment-view" style={{ padding: "20px" }}>
              {/* Header Card */}
              <div
                style={{
                  background: "var(--bg-surface-elevated)",
                  borderRadius: "10px",
                  padding: "18px 20px",
                  marginBottom: "20px",
                  border: "1px solid rgba(168, 85, 247, 0.3)",
                  boxShadow: "0 4px 12px rgba(0, 0, 0, 0.2)",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "14px" }}>
                  <div style={{ maxWidth: "750px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "8px" }}>
                      <span style={{ fontSize: "22px" }}>🛡️</span>
                      <h2 style={{ fontSize: "18px", fontWeight: "800", color: "#f8fafc", margin: 0 }}>
                        Claude Code Configuration Security Assessment
                      </h2>
                      <span
                        style={{
                          fontSize: "11px",
                          padding: "2px 8px",
                          borderRadius: "12px",
                          background: "rgba(168, 85, 247, 0.2)",
                          color: "#c084fc",
                          border: "1px solid rgba(168, 85, 247, 0.5)",
                          fontWeight: "700",
                        }}
                      >
                        ASI06 · LLM08 · ASI02
                      </span>
                    </div>
                    <p style={{ fontSize: "12px", color: "var(--text-muted)", margin: 0, lineHeight: "1.6" }}>
                      Autonomous security evaluation of Claude Code configuration files: project instructions (<code style={{ color: "#38bdf8" }}>CLAUDE.md</code>),
                      lifecycle hooks (<code style={{ color: "#38bdf8" }}>.claude/settings.json</code>), local tool permissions (<code style={{ color: "#38bdf8" }}>.claude/settings.local.json</code>),
                      and subagent directives (<code style={{ color: "#38bdf8" }}>.claude/agents/*.md</code>). All tests execute in a temporary isolated workspace with dynamic hook verification.
                    </p>
                  </div>

                  {/* Top Action Buttons */}
                  <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
                    <button
                      onClick={handleLoadClaudeSample}
                      disabled={isLoadingClaudeSample || isEvaluatingClaudeCode}
                      style={{
                        padding: "8px 14px",
                        borderRadius: "6px",
                        background: "rgba(168, 85, 247, 0.15)",
                        border: "1px solid rgba(168, 85, 247, 0.4)",
                        color: "#c084fc",
                        fontSize: "12px",
                        fontWeight: "700",
                        cursor: isLoadingClaudeSample ? "not-allowed" : "pointer",
                        display: "flex",
                        alignItems: "center",
                        gap: "6px",
                      }}
                    >
                      {isLoadingClaudeSample ? "⏳ Loading..." : "📥 Load Vulnerable Sample"}
                    </button>

                    <button
                      onClick={handleEvaluateClaudeCode}
                      disabled={isEvaluatingClaudeCode || isLoadingClaudeSample}
                      style={{
                        padding: "8px 16px",
                        borderRadius: "6px",
                        background: isEvaluatingClaudeCode ? "rgba(99, 102, 241, 0.5)" : "var(--accent-primary)",
                        border: "1px solid var(--accent-primary)",
                        color: "#ffffff",
                        fontSize: "12px",
                        fontWeight: "800",
                        cursor: isEvaluatingClaudeCode ? "not-allowed" : "pointer",
                        display: "flex",
                        alignItems: "center",
                        gap: "6px",
                        boxShadow: "0 2px 8px rgba(99, 102, 241, 0.4)",
                      }}
                    >
                      {isEvaluatingClaudeCode ? "⚙️ Evaluating in Sandbox..." : "🚀 Launch Security Assessment"}
                    </button>

                    {claudeCodeResult && (
                      <>
                        <button
                          onClick={() => handleExportClaudeCode("pdf")}
                          disabled={claudeCodeExporting !== null}
                          style={{
                            padding: "8px 14px",
                            borderRadius: "6px",
                            background: "rgba(239, 68, 68, 0.15)",
                            border: "1px solid rgba(239, 68, 68, 0.4)",
                            color: "var(--color-error, #ef4444)",
                            fontSize: "12px",
                            fontWeight: "700",
                            cursor: claudeCodeExporting ? "not-allowed" : "pointer",
                            display: "flex",
                            alignItems: "center",
                            gap: "6px",
                          }}
                        >
                          {claudeCodeExporting === "pdf" ? "⏳ Exporting..." : "📄 Download PDF"}
                        </button>

                        <button
                          onClick={() => handleExportClaudeCode("json")}
                          disabled={claudeCodeExporting !== null}
                          style={{
                            padding: "8px 14px",
                            borderRadius: "6px",
                            background: "rgba(34, 197, 94, 0.15)",
                            border: "1px solid rgba(34, 197, 94, 0.4)",
                            color: "var(--color-success, #22c55e)",
                            fontSize: "12px",
                            fontWeight: "700",
                            cursor: claudeCodeExporting ? "not-allowed" : "pointer",
                            display: "flex",
                            alignItems: "center",
                            gap: "6px",
                          }}
                        >
                          {claudeCodeExporting === "json" ? "⏳ Exporting..." : "📦 Download JSON"}
                        </button>
                      </>
                    )}
                  </div>
                </div>

                {/* Error Banner */}
                {claudeCodeError && (
                  <div
                    style={{
                      marginTop: "12px",
                      padding: "8px 12px",
                      borderRadius: "6px",
                      background: "rgba(239, 68, 68, 0.15)",
                      border: "1px solid rgba(239, 68, 68, 0.4)",
                      color: "#fca5a5",
                      fontSize: "12px",
                      display: "flex",
                      alignItems: "center",
                      gap: "8px",
                    }}
                  >
                    <span>⚠️</span>
                    <span>{claudeCodeError}</span>
                  </div>
                )}
              </div>

              {/* Configuration Files Input Section */}
              <div
                style={{
                  background: "var(--bg-surface)",
                  borderRadius: "10px",
                  border: "1px solid var(--border-subtle)",
                  padding: "16px",
                  marginBottom: "20px",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px", flexWrap: "wrap", gap: "8px" }}>
                  <div style={{ fontSize: "13px", fontWeight: "700", color: "#f8fafc", display: "flex", alignItems: "center", gap: "6px" }}>
                    <span>📝</span> Configuration Files Under Assessment
                  </div>
                  <div style={{ fontSize: "11px", color: "var(--text-dim)" }}>
                    Edit directly or click "Load Vulnerable Sample" above
                  </div>
                </div>

                {/* File Sub-Tabs */}
                <div style={{ display: "flex", gap: "4px", borderBottom: "1px solid var(--border-subtle)", marginBottom: "12px", overflowX: "auto" }}>
                  {[
                    { key: "claude_md", label: "CLAUDE.md", icon: "📋", badge: "Directives & Secrets" },
                    { key: "settings_json", label: ".claude/settings.json", icon: "⚙️", badge: "Hooks & Config" },
                    { key: "settings_local_json", label: ".claude/settings.local.json", icon: "🔑", badge: "Bash Permissions" },
                    { key: "report_writer_md", label: ".claude/agents/report-writer.md", icon: "🤖", badge: "Subagent Scope" },
                  ].map((tab) => (
                    <button
                      key={tab.key}
                      onClick={() => setClaudeCodeActiveFileTab(tab.key)}
                      style={{
                        padding: "8px 14px",
                        background: claudeCodeActiveFileTab === tab.key ? "var(--bg-surface-elevated)" : "transparent",
                        color: claudeCodeActiveFileTab === tab.key ? "var(--accent-cyan)" : "var(--text-muted)",
                        border: "none",
                        borderBottom: claudeCodeActiveFileTab === tab.key ? "2px solid var(--accent-cyan)" : "none",
                        fontSize: "12px",
                        fontWeight: claudeCodeActiveFileTab === tab.key ? "700" : "500",
                        cursor: "pointer",
                        display: "flex",
                        alignItems: "center",
                        gap: "6px",
                        whiteSpace: "nowrap",
                      }}
                    >
                      <span>{tab.icon}</span>
                      <span>{tab.label}</span>
                      <span
                        style={{
                          fontSize: "10px",
                          padding: "1px 6px",
                          borderRadius: "4px",
                          background: "rgba(255, 255, 255, 0.05)",
                          color: "var(--text-dim)",
                        }}
                      >
                        {tab.badge}
                      </span>
                    </button>
                  ))}
                </div>

                {/* File Editor Textarea */}
                <div style={{ position: "relative" }}>
                  <textarea
                    rows={12}
                    value={claudeCodeFiles[claudeCodeActiveFileTab] || ""}
                    onChange={(e) =>
                      setClaudeCodeFiles({
                        ...claudeCodeFiles,
                        [claudeCodeActiveFileTab]: e.target.value,
                      })
                    }
                    placeholder={`Paste or edit ${claudeCodeActiveFileTab} contents here...`}
                    style={{
                      width: "100%",
                      padding: "12px 14px",
                      background: "#020617",
                      border: "1px solid var(--border-subtle)",
                      borderRadius: "6px",
                      color: "#38bdf8",
                      fontFamily: "DM Mono, Consolas, monospace",
                      fontSize: "12px",
                      lineHeight: "1.5",
                      resize: "vertical",
                      boxSizing: "border-box",
                    }}
                  />
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      marginTop: "6px",
                      fontSize: "11px",
                      color: "var(--text-dim)",
                    }}
                  >
                    <span>
                      Length: {(claudeCodeFiles[claudeCodeActiveFileTab] || "").length} characters | Lines: {(claudeCodeFiles[claudeCodeActiveFileTab] || "").split("\n").length}
                    </span>
                    <span style={{ color: "var(--color-success, #22c55e)", display: "flex", alignItems: "center", gap: "4px" }}>
                      🔒 Ephemeral Sandbox Isolation: Target files materialized only in <code style={{ color: "#cbd5e1" }}>tempfile.mkdtemp</code>
                    </span>
                  </div>
                </div>
              </div>

              {/* Assessment Results Section */}
              {claudeCodeResult && (
                <div>
                  {/* Verdict Banner */}
                  <div
                    style={{
                      background:
                        claudeCodeResult.verdict === "CRITICAL_RISK"
                          ? "rgba(239, 68, 68, 0.12)"
                          : claudeCodeResult.verdict === "VULNERABLE"
                          ? "rgba(234, 179, 8, 0.12)"
                          : "rgba(34, 197, 94, 0.12)",
                      border: `1px solid ${
                        claudeCodeResult.verdict === "CRITICAL_RISK"
                          ? "rgba(239, 68, 68, 0.4)"
                          : claudeCodeResult.verdict === "VULNERABLE"
                          ? "rgba(234, 179, 8, 0.4)"
                          : "rgba(34, 197, 94, 0.4)"
                      }`,
                      borderRadius: "10px",
                      padding: "16px 20px",
                      marginBottom: "20px",
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "12px" }}>
                      <div>
                        <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "4px" }}>
                          <span style={{ fontSize: "20px" }}>
                            {claudeCodeResult.verdict === "CRITICAL_RISK" ? "🚨" : claudeCodeResult.verdict === "VULNERABLE" ? "⚠️" : "✅"}
                          </span>
                          <span style={{ fontSize: "16px", fontWeight: "800", color: "#f8fafc" }}>
                            Assessment Verdict: {claudeCodeResult.verdict.replace("_", " ")}
                          </span>
                          <span
                            style={{
                              padding: "2px 8px",
                              borderRadius: "12px",
                              fontSize: "11px",
                              fontWeight: "700",
                              background: claudeCodeResult.execution_status === "PASSED" ? "rgba(34, 197, 94, 0.2)" : "rgba(239, 68, 68, 0.2)",
                              color: claudeCodeResult.execution_status === "PASSED" ? "#22c55e" : "#ef4444",
                              border: `1px solid ${claudeCodeResult.execution_status === "PASSED" ? "rgba(34, 197, 94, 0.5)" : "rgba(239, 68, 68, 0.5)"}`,
                            }}
                          >
                            DYNAMIC EXECUTION: {claudeCodeResult.execution_status}
                          </span>
                        </div>
                        <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                          Evaluation ID: <code style={{ color: "#38bdf8" }}>{claudeCodeResult.evaluation_id}</code> | Timestamp: {claudeCodeResult.timestamp}
                        </div>
                      </div>

                      {/* Summary Metrics Chips */}
                      <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
                        <div style={{ padding: "6px 12px", borderRadius: "6px", background: "rgba(0,0,0,0.3)", textAlign: "center", border: "1px solid var(--border-subtle)" }}>
                          <div style={{ fontSize: "16px", fontWeight: "800", color: "#f8fafc" }}>{claudeCodeResult.summary?.total_findings || 0}</div>
                          <div style={{ fontSize: "10px", color: "var(--text-dim)", textTransform: "uppercase" }}>Total Findings</div>
                        </div>
                        <div style={{ padding: "6px 12px", borderRadius: "6px", background: "rgba(239, 68, 68, 0.2)", textAlign: "center", border: "1px solid rgba(239, 68, 68, 0.4)" }}>
                          <div style={{ fontSize: "16px", fontWeight: "800", color: "var(--color-error, #ef4444)" }}>{claudeCodeResult.summary?.findings_by_severity?.CRITICAL || 0}</div>
                          <div style={{ fontSize: "10px", color: "#fca5a5", textTransform: "uppercase" }}>Critical</div>
                        </div>
                        <div style={{ padding: "6px 12px", borderRadius: "6px", background: "rgba(249, 115, 22, 0.2)", textAlign: "center", border: "1px solid rgba(249, 115, 22, 0.4)" }}>
                          <div style={{ fontSize: "16px", fontWeight: "800", color: "#f97316" }}>{claudeCodeResult.summary?.findings_by_severity?.HIGH || 0}</div>
                          <div style={{ fontSize: "10px", color: "#fed7aa", textTransform: "uppercase" }}>High</div>
                        </div>
                        <div style={{ padding: "6px 12px", borderRadius: "6px", background: "rgba(234, 179, 8, 0.2)", textAlign: "center", border: "1px solid rgba(234, 179, 8, 0.4)" }}>
                          <div style={{ fontSize: "16px", fontWeight: "800", color: "#eab308" }}>{claudeCodeResult.summary?.findings_by_severity?.MEDIUM || 0}</div>
                          <div style={{ fontSize: "10px", color: "#fef08a", textTransform: "uppercase" }}>Medium</div>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Grid Layout: Hook Testing & Core Diagnostic Cards */}
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(420px, 1fr))", gap: "16px", marginBottom: "20px" }}>
                    {/* Card 1: Dynamic PostToolUse Hook Testing */}
                    <div
                      style={{
                        background: "var(--bg-surface)",
                        borderRadius: "10px",
                        border: "1px solid var(--border-subtle)",
                        padding: "16px",
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
                        <div style={{ fontSize: "13px", fontWeight: "800", color: "#f8fafc", display: "flex", alignItems: "center", gap: "6px" }}>
                          <span>🪝</span> Dynamic Hook Execution (PostToolUse)
                        </div>
                        <span
                          style={{
                            padding: "2px 8px",
                            borderRadius: "4px",
                            fontSize: "11px",
                            fontWeight: "700",
                            background: claudeCodeResult.hook_execution?.marker_file_created ? "rgba(34, 197, 94, 0.2)" : "rgba(239, 68, 68, 0.2)",
                            color: claudeCodeResult.hook_execution?.marker_file_created ? "#22c55e" : "#ef4444",
                          }}
                        >
                          {claudeCodeResult.hook_execution?.marker_file_created ? "MARKER VERIFIED ON DISK" : "MARKER CREATION FAILED"}
                        </span>
                      </div>

                      <div style={{ fontSize: "11px", color: "var(--text-muted)", marginBottom: "10px" }}>
                        ApexShield configured a controlled PostToolUse hook inside the isolated workspace and executed a controlled marker probe to verify dynamic triggering.
                      </div>

                      <div style={{ background: "#020617", padding: "10px 12px", borderRadius: "6px", border: "1px solid var(--border-subtle)", marginBottom: "10px" }}>
                        <div style={{ fontSize: "10px", color: "var(--text-dim)", textTransform: "uppercase", marginBottom: "2px" }}>Hook Command Dispatched:</div>
                        <code style={{ fontSize: "11px", color: "var(--accent-cyan)", fontFamily: "DM Mono, monospace", wordBreak: "break-all" }}>
                          {claudeCodeResult.hook_execution?.command || "None"}
                        </code>
                      </div>

                      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px", fontSize: "11px", marginBottom: "10px" }}>
                        <div style={{ padding: "8px", background: "rgba(255,255,255,0.02)", borderRadius: "4px", border: "1px solid var(--border-subtle)" }}>
                          <span style={{ color: "var(--text-dim)" }}>Duration: </span>
                          <span style={{ fontWeight: "700", color: "#f8fafc" }}>{claudeCodeResult.hook_execution?.duration_ms} ms</span>
                        </div>
                        <div style={{ padding: "8px", background: "rgba(255,255,255,0.02)", borderRadius: "4px", border: "1px solid var(--border-subtle)" }}>
                          <span style={{ color: "var(--text-dim)" }}>Exit Code: </span>
                          <span style={{ fontWeight: "700", color: claudeCodeResult.hook_execution?.exit_code === 0 ? "#22c55e" : "#ef4444" }}>
                            {claudeCodeResult.hook_execution?.exit_code}
                          </span>
                        </div>
                      </div>

                      {claudeCodeResult.hook_execution?.marker_file_content && (
                        <div style={{ padding: "8px 10px", background: "rgba(34, 197, 94, 0.08)", borderRadius: "4px", border: "1px solid rgba(34, 197, 94, 0.2)", fontSize: "11px", marginBottom: "10px" }}>
                          <span style={{ fontWeight: "700", color: "#22c55e" }}>Marker Content: </span>
                          <code style={{ color: "#cbd5e1", fontFamily: "DM Mono, monospace" }}>
                            {claudeCodeResult.hook_execution.marker_file_content}
                          </code>
                        </div>
                      )}

                      <div style={{ padding: "8px 10px", background: "rgba(99, 102, 241, 0.08)", borderRadius: "4px", border: "1px solid rgba(99, 102, 241, 0.2)", fontSize: "10px", color: "var(--accent-cyan)" }}>
                        🛡️ Safety Containment: Hazardous shell command patterns (e.g. destructive deletions or remote curls) are automatically blocked by the evaluator sandbox.
                      </div>
                    </div>

                    {/* Card 2: Local Permissions & Wildcard Bash Analysis */}
                    <div
                      style={{
                        background: "var(--bg-surface)",
                        borderRadius: "10px",
                        border: "1px solid var(--border-subtle)",
                        padding: "16px",
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
                        <div style={{ fontSize: "13px", fontWeight: "800", color: "#f8fafc", display: "flex", alignItems: "center", gap: "6px" }}>
                          <span>🔑</span> Tool Access & Permissions Boundary
                        </div>
                        <span
                          style={{
                            padding: "2px 8px",
                            borderRadius: "4px",
                            fontSize: "11px",
                            fontWeight: "700",
                            background: "rgba(239, 68, 68, 0.2)",
                            color: "var(--color-error, #ef4444)",
                            border: "1px solid rgba(239, 68, 68, 0.4)",
                          }}
                        >
                          ASI02 · CRITICAL
                        </span>
                      </div>

                      <div style={{ padding: "10px 12px", background: "rgba(239, 68, 68, 0.1)", borderRadius: "6px", border: "1px solid rgba(239, 68, 68, 0.3)", marginBottom: "12px" }}>
                        <div style={{ fontSize: "12px", fontWeight: "700", color: "#fca5a5", marginBottom: "4px" }}>
                          🚨 Unrestricted Shell Tool: Bash(*) Wildcard
                        </div>
                        <div style={{ fontSize: "11px", color: "#cbd5e1", lineHeight: "1.5" }}>
                          File <code style={{ color: "#38bdf8" }}>.claude/settings.local.json</code> grants unconstrained wildcard shell access (<code style={{ color: "#fca5a5" }}>Bash(*)</code>).
                          This allows the agent to execute any arbitrary terminal command without prompting the user.
                        </div>
                      </div>

                      <div style={{ fontSize: "11px", color: "var(--text-muted)", marginBottom: "10px", lineHeight: "1.5" }}>
                        <strong style={{ color: "#f8fafc" }}>Security Rule: </strong>
                        ApexShield strictly prohibits auto-executing unrestricted shell tools. Instead, strict command allowlists with path arguments (e.g., <code style={{ color: "#38bdf8" }}>pytest tests/</code>) must be configured.
                      </div>

                      <div style={{ background: "#020617", padding: "10px 12px", borderRadius: "6px", border: "1px solid var(--border-subtle)", fontSize: "11px" }}>
                        <div style={{ fontSize: "10px", color: "var(--text-dim)", textTransform: "uppercase", marginBottom: "2px" }}>Remediation Control:</div>
                        <code style={{ color: "#22c55e", fontFamily: "DM Mono, monospace" }}>
                          "allow": ["Bash(pytest tests/*)", "Bash(git status)"]
                        </code>
                      </div>
                    </div>
                  </div>

                  {/* Isolated Target Workspace Manifest */}
                  <div
                    style={{
                      background: "var(--bg-surface)",
                      borderRadius: "10px",
                      border: "1px solid var(--border-subtle)",
                      padding: "16px",
                      marginBottom: "20px",
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
                      <div style={{ fontSize: "13px", fontWeight: "800", color: "#f8fafc", display: "flex", alignItems: "center", gap: "6px" }}>
                        <span>📁</span> Isolated Workspace & Cryptographic File Manifest
                      </div>
                      <span style={{ fontSize: "11px", color: "var(--text-dim)", fontFamily: "DM Mono, monospace" }}>
                        {claudeCodeResult.target_workspace}
                      </span>
                    </div>

                    <div style={{ overflowX: "auto" }}>
                      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "11px" }}>
                        <thead>
                          <tr style={{ borderBottom: "1px solid var(--border-subtle)", color: "var(--text-dim)", textAlign: "left" }}>
                            <th style={{ padding: "8px 10px" }}>File Relative Path</th>
                            <th style={{ padding: "8px 10px" }}>Size</th>
                            <th style={{ padding: "8px 10px" }}>SHA-256 Digest</th>
                            <th style={{ padding: "8px 10px" }}>Isolated Host Path</th>
                          </tr>
                        </thead>
                        <tbody>
                          {(Array.isArray(claudeCodeResult.files_evaluated)
                            ? claudeCodeResult.files_evaluated
                            : Object.values(claudeCodeResult.files_evaluated || {})
                          ).map((fmeta, fidx) => (
                            <tr key={fmeta.relative_path || fmeta.name || fidx} style={{ borderBottom: "1px solid rgba(255,255,255,0.03)" }}>
                              <td style={{ padding: "8px 10px", fontWeight: "700", color: "var(--accent-cyan)" }}>
                                {fmeta.relative_path || fmeta.name}
                              </td>
                              <td style={{ padding: "8px 10px", color: "var(--text-muted)" }}>{fmeta.size_bytes} B</td>
                              <td style={{ padding: "8px 10px", fontFamily: "DM Mono, monospace", color: "#94a3b8" }}>
                                {fmeta.sha256?.slice(0, 16)}...{fmeta.sha256?.slice(-8)}
                              </td>
                              <td style={{ padding: "8px 10px", fontFamily: "DM Mono, monospace", color: "var(--text-dim)", fontSize: "10px" }}>
                                {fmeta.isolated_absolute_path || fmeta.isolated_path}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  {/* Security Findings Register */}
                  <div
                    style={{
                      background: "var(--bg-surface)",
                      borderRadius: "10px",
                      border: "1px solid var(--border-subtle)",
                      padding: "16px",
                      marginBottom: "20px",
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
                      <div style={{ fontSize: "14px", fontWeight: "800", color: "#f8fafc", display: "flex", alignItems: "center", gap: "8px" }}>
                        <span>📋</span> Detailed Security Findings Register ({claudeCodeResult.findings?.length || 0})
                      </div>
                      <div style={{ fontSize: "11px", color: "var(--text-dim)" }}>
                        Mapped to OWASP Top 10 for LLMs & Agentic Security
                      </div>
                    </div>

                    <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                      {(claudeCodeResult.findings || []).map((finding) => (
                        <div
                          key={finding.id}
                          style={{
                            background: "var(--bg-surface-elevated)",
                            borderRadius: "8px",
                            border: `1px solid ${
                              finding.severity === "CRITICAL"
                                ? "rgba(239, 68, 68, 0.4)"
                                : finding.severity === "HIGH"
                                ? "rgba(249, 115, 22, 0.4)"
                                : "rgba(234, 179, 8, 0.4)"
                            }`,
                            padding: "14px 16px",
                          }}
                        >
                          {/* Finding Header */}
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "8px", flexWrap: "wrap", gap: "8px" }}>
                            <div>
                              <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
                                <span
                                  style={{
                                    padding: "2px 8px",
                                    borderRadius: "4px",
                                    fontSize: "11px",
                                    fontWeight: "800",
                                    background:
                                      finding.severity === "CRITICAL"
                                        ? "rgba(239, 68, 68, 0.2)"
                                        : finding.severity === "HIGH"
                                        ? "rgba(249, 115, 22, 0.2)"
                                        : "rgba(234, 179, 8, 0.2)",
                                    color:
                                      finding.severity === "CRITICAL"
                                        ? "var(--color-error, #ef4444)"
                                        : finding.severity === "HIGH"
                                        ? "#f97316"
                                        : "#eab308",
                                  }}
                                >
                                  {finding.severity}
                                </span>
                                <span
                                  style={{
                                    padding: "2px 8px",
                                    borderRadius: "4px",
                                    fontSize: "11px",
                                    fontWeight: "700",
                                    background: "rgba(99, 102, 241, 0.2)",
                                    color: "var(--accent-primary)",
                                    border: "1px solid rgba(99, 102, 241, 0.4)",
                                  }}
                                >
                                  {finding.risk_id}
                                </span>
                                <span style={{ fontSize: "14px", fontWeight: "700", color: "#f8fafc" }}>
                                  {finding.title}
                                </span>
                              </div>
                              <div style={{ fontSize: "11px", color: "var(--text-muted)", display: "flex", gap: "10px" }}>
                                <span>File: <code style={{ color: "#38bdf8" }}>{finding.file}</code></span>
                                {finding.line_number && <span>Line: {finding.line_number}</span>}
                                <span>CVSS: <strong style={{ color: "#f8fafc" }}>{finding.cvss_score}</strong></span>
                              </div>
                            </div>
                          </div>

                          {/* Root Cause & Impact */}
                          <div style={{ fontSize: "12px", color: "#cbd5e1", lineHeight: "1.5", marginBottom: "8px" }}>
                            <strong style={{ color: "#f8fafc" }}>Root Cause: </strong>{finding.root_cause}
                          </div>
                          <div style={{ fontSize: "12px", color: "var(--text-muted)", lineHeight: "1.5", marginBottom: "10px" }}>
                            <strong style={{ color: "#f8fafc" }}>Impact: </strong>{finding.impact}
                          </div>

                          {/* Evidence */}
                          {finding.evidence && (
                            <div style={{ marginBottom: "10px" }}>
                              <div style={{ fontSize: "10px", color: "var(--text-dim)", textTransform: "uppercase", marginBottom: "2px" }}>Evidence:</div>
                              <pre
                                style={{
                                  margin: 0,
                                  padding: "8px 12px",
                                  background: "#020617",
                                  borderRadius: "4px",
                                  border: "1px solid var(--border-subtle)",
                                  color: "#cbd5e1",
                                  fontFamily: "DM Mono, monospace",
                                  fontSize: "11px",
                                  overflowX: "auto",
                                }}
                              >
                                {finding.evidence}
                              </pre>
                            </div>
                          )}

                          {/* Remediation Code */}
                          {finding.remediation_code && (
                            <div style={{ position: "relative" }}>
                              <div
                                style={{
                                  display: "flex",
                                  justifyContent: "space-between",
                                  alignItems: "center",
                                  background: "#0f172a",
                                  padding: "4px 10px",
                                  borderTopLeftRadius: "4px",
                                  borderTopRightRadius: "4px",
                                  border: "1px solid rgba(255,255,255,0.08)",
                                  borderBottom: "none",
                                }}
                              >
                                <span style={{ fontSize: "10px", color: "var(--color-success, #22c55e)", fontWeight: "700", textTransform: "uppercase" }}>
                                  Recommended Remediation Fix
                                </span>
                                <button
                                  onClick={() => {
                                    navigator.clipboard.writeText(finding.remediation_code);
                                    setCopiedRemediationId(finding.id);
                                    setTimeout(() => setCopiedRemediationId(null), 2500);
                                  }}
                                  style={{
                                    padding: "2px 8px",
                                    borderRadius: "4px",
                                    background: "rgba(34, 197, 94, 0.2)",
                                    border: "1px solid rgba(34, 197, 94, 0.4)",
                                    color: "#22c55e",
                                    fontSize: "10px",
                                    cursor: "pointer",
                                    display: "flex",
                                    alignItems: "center",
                                    gap: "4px",
                                  }}
                                >
                                  {copiedRemediationId === finding.id ? "✅ Copied" : "📋 Copy Fix"}
                                </button>
                              </div>
                              <pre
                                style={{
                                  margin: 0,
                                  padding: "8px 12px",
                                  background: "#020617",
                                  borderBottomLeftRadius: "4px",
                                  borderBottomRightRadius: "4px",
                                  border: "1px solid rgba(255,255,255,0.08)",
                                  color: "#86efac",
                                  fontFamily: "DM Mono, monospace",
                                  fontSize: "11px",
                                  overflowX: "auto",
                                }}
                              >
                                {finding.remediation_code}
                              </pre>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB: Operations Monitoring & Auditability (Phase E8) */}
          {activeTab === "operations" && (
            <div>
              {/* Controls & Status Bar */}
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px", padding: "16px", background: "var(--bg-surface)", border: "1px solid var(--border-subtle)", borderRadius: "10px" }}>
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
                    <h3 style={{ fontSize: "16px", fontWeight: "700", color: "var(--text-main)", margin: 0 }}>
                      ⚡ Operations Monitoring & Auditability SOC
                    </h3>
                    <span style={{
                      padding: "2px 8px",
                      borderRadius: "12px",
                      fontSize: "10px",
                      fontWeight: "800",
                      background: operationsHealth?.status === "HEALTHY" ? "rgba(34, 197, 94, 0.15)" : (operationsHealth?.status === "DEGRADED" ? "rgba(234, 179, 8, 0.15)" : "rgba(239, 68, 68, 0.15)"),
                      color: operationsHealth?.status === "HEALTHY" ? "var(--color-success, #22c55e)" : (operationsHealth?.status === "DEGRADED" ? "var(--color-warning, #eab308)" : "var(--color-danger, #ef4444)"),
                      border: `1px solid ${operationsHealth?.status === "HEALTHY" ? "rgba(34, 197, 94, 0.3)" : (operationsHealth?.status === "DEGRADED" ? "rgba(234, 179, 8, 0.3)" : "rgba(239, 68, 68, 0.3)")}`,
                    }}>
                      {operationsHealth?.status || "LIVE TELEMETRY"}
                    </span>
                  </div>
                  <p style={{ fontSize: "12px", color: "var(--text-muted)", margin: 0 }}>
                    Real-time execution telemetry, cryptographic HMAC evidence audit status, distributed trace identifiers, and per-session circuit breakers.
                  </p>
                </div>
                <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
                  <button
                    onClick={handleFetchOperationsAll}
                    disabled={isFetchingOperations}
                    style={{
                      padding: "8px 14px",
                      background: "var(--accent-primary)",
                      color: "#fff",
                      border: "none",
                      borderRadius: "6px",
                      fontSize: "12px",
                      fontWeight: "600",
                      cursor: "pointer",
                      display: "flex",
                      alignItems: "center",
                      gap: "6px",
                    }}
                  >
                    {isFetchingOperations ? "Refreshing..." : "🔄 Refresh Telemetry"}
                  </button>
                </div>
              </div>

              {/* Action Feedback Banner */}
              {opsActionFeedback && (
                <div style={{
                  padding: "12px 16px",
                  borderRadius: "8px",
                  marginBottom: "16px",
                  fontSize: "12px",
                  fontWeight: "600",
                  background: opsActionFeedback.type === "success" ? "rgba(34, 197, 94, 0.12)" : "rgba(239, 68, 68, 0.12)",
                  color: opsActionFeedback.type === "success" ? "var(--color-success, #22c55e)" : "var(--color-danger, #ef4444)",
                  border: `1px solid ${opsActionFeedback.type === "success" ? "rgba(34, 197, 94, 0.3)" : "rgba(239, 68, 68, 0.3)"}`,
                }}>
                  {opsActionFeedback.message}
                </div>
              )}

              {/* KPI Grid */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))", gap: "12px", marginBottom: "20px" }}>
                <div style={{ background: "var(--bg-surface)", border: "1px solid var(--border-subtle)", borderRadius: "10px", padding: "16px" }}>
                  <div style={{ fontSize: "11px", fontWeight: "600", color: "var(--text-muted)", marginBottom: "4px" }}>ACTIVE SESSIONS</div>
                  <div style={{ fontSize: "24px", fontWeight: "800", color: "var(--accent-cyan)" }}>
                    {operationsOverview?.active_sessions_count ?? 0}
                  </div>
                  <div style={{ fontSize: "11px", color: "var(--text-dim)", marginTop: "4px" }}>
                    In-Flight Probes: <span style={{ fontWeight: "700", color: "var(--text-main)" }}>{operationsOverview?.concurrent_probes ?? 0}</span>
                  </div>
                </div>

                <div style={{ background: "var(--bg-surface)", border: "1px solid var(--border-subtle)", borderRadius: "10px", padding: "16px" }}>
                  <div style={{ fontSize: "11px", fontWeight: "600", color: "var(--text-muted)", marginBottom: "4px" }}>THROUGHPUT</div>
                  <div style={{ fontSize: "24px", fontWeight: "800", color: "var(--accent-primary)" }}>
                    {operationsOverview?.throughput_per_second ?? 0} <span style={{ fontSize: "12px", fontWeight: "600" }}>req/s</span>
                  </div>
                  <div style={{ fontSize: "11px", color: "var(--text-dim)", marginTop: "4px" }}>
                    60-sec Window: <span style={{ fontWeight: "700", color: "var(--text-main)" }}>{operationsOverview?.throughput_per_minute ?? 0} req/min</span>
                  </div>
                </div>

                <div style={{ background: "var(--bg-surface)", border: "1px solid var(--border-subtle)", borderRadius: "10px", padding: "16px" }}>
                  <div style={{ fontSize: "11px", fontWeight: "600", color: "var(--text-muted)", marginBottom: "4px" }}>LATENCY DISTRIBUTION</div>
                  <div style={{ fontSize: "13px", fontWeight: "700", color: "var(--text-main)", display: "flex", justifyContent: "space-between", marginTop: "6px" }}>
                    <span>p50: <span style={{ color: "var(--accent-cyan)" }}>{operationsOverview?.latency_p50_ms ?? 0}ms</span></span>
                    <span>p95: <span style={{ color: "var(--accent-primary)" }}>{operationsOverview?.latency_p95_ms ?? 0}ms</span></span>
                    <span>p99: <span style={{ color: "var(--color-warning, #eab308)" }}>{operationsOverview?.latency_p99_ms ?? 0}ms</span></span>
                  </div>
                  <div style={{ fontSize: "11px", color: "var(--text-dim)", marginTop: "8px" }}>
                    Total Requests: <span style={{ fontWeight: "700", color: "var(--text-main)" }}>{operationsOverview?.total_requests ?? 0}</span>
                  </div>
                </div>

                <div style={{ background: "var(--bg-surface)", border: "1px solid var(--border-subtle)", borderRadius: "10px", padding: "16px" }}>
                  <div style={{ fontSize: "11px", fontWeight: "600", color: "var(--text-muted)", marginBottom: "4px" }}>ERROR & ANOMALY RATES</div>
                  <div style={{ fontSize: "13px", fontWeight: "700", display: "flex", justifyContent: "space-between", marginTop: "6px" }}>
                    <span>4xx: <span style={{ color: "var(--text-main)" }}>{(operationsOverview?.error_rates?.rate_4xx * 100 || 0).toFixed(1)}%</span></span>
                    <span>5xx: <span style={{ color: "var(--color-danger, #ef4444)" }}>{(operationsOverview?.error_rates?.rate_5xx * 100 || 0).toFixed(1)}%</span></span>
                  </div>
                  <div style={{ fontSize: "11px", color: "var(--text-dim)", marginTop: "8px" }}>
                    Timeouts: {operationsOverview?.timeouts_count ?? 0} | Cancelled: {operationsOverview?.cancellations_count ?? 0}
                  </div>
                </div>
              </div>

              {/* Two Column Layout: HMAC Cryptographic Audit + Per-Session Circuit Breakers */}
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
                {/* Column 1: HMAC Evidence Audit Monitor */}
                <div style={{ background: "var(--bg-surface)", border: "1px solid var(--border-subtle)", borderRadius: "10px", padding: "16px" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px", borderBottom: "1px solid var(--border-subtle)", paddingBottom: "8px" }}>
                    <div style={{ fontSize: "14px", fontWeight: "700", color: "var(--text-main)" }}>
                      🔐 HMAC Evidence Audit Monitor
                    </div>
                    <span style={{
                      padding: "2px 8px",
                      borderRadius: "10px",
                      fontSize: "10px",
                      fontWeight: "700",
                      background: hmacAuditData?.tampering_events > 0 ? "rgba(239, 68, 68, 0.15)" : "rgba(34, 197, 94, 0.15)",
                      color: hmacAuditData?.tampering_events > 0 ? "var(--color-danger, #ef4444)" : "var(--color-success, #22c55e)",
                    }}>
                      {hmacAuditData?.health_status || "HEALTHY"}
                    </span>
                  </div>

                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px", marginBottom: "16px" }}>
                    <div style={{ background: "var(--bg-surface-elevated)", padding: "10px", borderRadius: "6px" }}>
                      <div style={{ fontSize: "10px", color: "var(--text-muted)" }}>VERIFIED PROOFS</div>
                      <div style={{ fontSize: "18px", fontWeight: "800", color: "var(--color-success, #22c55e)" }}>
                        {hmacAuditData?.successful_verifications ?? 0}
                      </div>
                    </div>
                    <div style={{ background: "var(--bg-surface-elevated)", padding: "10px", borderRadius: "6px" }}>
                      <div style={{ fontSize: "10px", color: "var(--text-muted)" }}>TAMPERING DETECTIONS</div>
                      <div style={{ fontSize: "18px", fontWeight: "800", color: hmacAuditData?.tampering_events > 0 ? "var(--color-danger, #ef4444)" : "var(--text-muted)" }}>
                        {hmacAuditData?.tampering_events ?? 0}
                      </div>
                    </div>
                    <div style={{ background: "var(--bg-surface-elevated)", padding: "10px", borderRadius: "6px" }}>
                      <div style={{ fontSize: "10px", color: "var(--text-muted)" }}>INVALID SIGNATURES</div>
                      <div style={{ fontSize: "18px", fontWeight: "800", color: hmacAuditData?.invalid_signatures > 0 ? "var(--color-warning, #eab308)" : "var(--text-muted)" }}>
                        {hmacAuditData?.invalid_signatures ?? 0}
                      </div>
                    </div>
                    <div style={{ background: "var(--bg-surface-elevated)", padding: "10px", borderRadius: "6px" }}>
                      <div style={{ fontSize: "10px", color: "var(--text-muted)" }}>SUCCESS RATIO</div>
                      <div style={{ fontSize: "18px", fontWeight: "800", color: "var(--accent-cyan)" }}>
                        {((hmacAuditData?.verification_success_rate ?? 1.0) * 100).toFixed(1)}%
                      </div>
                    </div>
                  </div>

                  <h5 style={{ fontSize: "12px", fontWeight: "700", color: "var(--text-main)", marginBottom: "8px" }}>
                    Recent Integrity Alerts & Verification Events
                  </h5>
                  {hmacAuditData?.recent_alerts?.length === 0 ? (
                    <div style={{ padding: "20px", textAlign: "center", color: "var(--text-dim)", fontSize: "11px", background: "var(--bg-surface-elevated)", borderRadius: "6px" }}>
                      🛡️ Zero cryptographic integrity anomalies or tampering detected.
                    </div>
                  ) : (
                    <div style={{ maxHeight: "200px", overflowY: "auto", display: "flex", flexDirection: "column", gap: "6px" }}>
                      {hmacAuditData?.recent_alerts?.map((alt, idx) => (
                        <div key={idx} style={{ padding: "8px 10px", background: "rgba(239, 68, 68, 0.08)", border: "1px solid rgba(239, 68, 68, 0.25)", borderRadius: "6px", fontSize: "11px" }}>
                          <div style={{ display: "flex", justifyContent: "space-between", fontWeight: "700", color: "var(--color-danger, #ef4444)" }}>
                            <span>{alt.alert_type}</span>
                            <span style={{ fontSize: "10px" }}>{alt.severity}</span>
                          </div>
                          <div style={{ color: "var(--text-main)", marginTop: "2px" }}>{alt.details}</div>
                          <div style={{ fontSize: "10px", color: "var(--text-muted)", marginTop: "2px" }}>Ref: {alt.target_ref}</div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Column 2: Per-Session Circuit Breakers & Request Budgets */}
                <div style={{ background: "var(--bg-surface)", border: "1px solid var(--border-subtle)", borderRadius: "10px", padding: "16px" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px", borderBottom: "1px solid var(--border-subtle)", paddingBottom: "8px" }}>
                    <div style={{ fontSize: "14px", fontWeight: "700", color: "var(--text-main)" }}>
                      ⚡ Per-Session Circuit Breakers
                    </div>
                    <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                      Total Circuits: <span style={{ fontWeight: "700", color: "var(--text-main)" }}>{circuitBreakers.length}</span>
                    </span>
                  </div>

                  {/* Administrative Reset Controls */}
                  <div style={{ background: "var(--bg-surface-elevated)", padding: "10px 12px", borderRadius: "8px", marginBottom: "14px" }}>
                    <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--text-main)", marginBottom: "6px" }}>
                      Administrative Circuit Reset Controls
                    </div>
                    <div style={{ display: "flex", gap: "8px" }}>
                      <input
                        type="password"
                        placeholder="Admin Token..."
                        value={opsAdminToken}
                        onChange={(e) => setOpsAdminToken(e.target.value)}
                        style={{
                          flex: 1,
                          background: "var(--bg-surface)",
                          color: "var(--text-main)",
                          border: "1px solid var(--border-subtle)",
                          borderRadius: "4px",
                          padding: "6px 8px",
                          fontSize: "11px",
                        }}
                      />
                      <button
                        onClick={() => handleResetCircuitBreakers(opsResetSessionId || null)}
                        style={{
                          padding: "6px 12px",
                          background: "var(--accent-primary)",
                          color: "#fff",
                          border: "none",
                          borderRadius: "4px",
                          fontSize: "11px",
                          fontWeight: "600",
                          cursor: "pointer",
                        }}
                      >
                        Reset All Circuits
                      </button>
                    </div>
                  </div>

                  {/* Circuit Breakers List */}
                  {circuitBreakers.length === 0 ? (
                    <div style={{ padding: "20px", textAlign: "center", color: "var(--text-dim)", fontSize: "11px", background: "var(--bg-surface-elevated)", borderRadius: "6px" }}>
                      ℹ️ No active assessment circuits initialized yet. Circuits instantiate upon probe dispatch.
                    </div>
                  ) : (
                    <div style={{ maxHeight: "220px", overflowY: "auto", display: "flex", flexDirection: "column", gap: "8px" }}>
                      {circuitBreakers.map((cb, idx) => (
                        <div key={idx} style={{ padding: "10px", background: "var(--bg-surface-elevated)", border: "1px solid var(--border-subtle)", borderRadius: "6px" }}>
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
                            <span style={{ fontSize: "12px", fontWeight: "700", color: "var(--text-main)" }}>
                              Session: {cb.session_id}
                            </span>
                            <span style={{
                              padding: "2px 6px",
                              borderRadius: "4px",
                              fontSize: "10px",
                              fontWeight: "700",
                              background: cb.state === "CLOSED" ? "rgba(34, 197, 94, 0.15)" : (cb.state === "HALF_OPEN" ? "rgba(234, 179, 8, 0.15)" : "rgba(239, 68, 68, 0.15)"),
                              color: cb.state === "CLOSED" ? "var(--color-success, #22c55e)" : (cb.state === "HALF_OPEN" ? "var(--color-warning, #eab308)" : "var(--color-danger, #ef4444)"),
                            }}>
                              {cb.state}
                            </span>
                          </div>
                          <div style={{ fontSize: "11px", color: "var(--text-muted)", marginBottom: "4px" }}>
                            Budget: {cb.requests_dispatched} / {cb.request_budget} ({cb.budget_utilization_pct}%) | Errors: {cb.consecutive_errors} (429: {cb.consecutive_429}, 503: {cb.consecutive_503})
                          </div>
                          {cb.trip_reason && (
                            <div style={{ fontSize: "10px", color: "var(--color-danger, #ef4444)", marginTop: "2px" }}>
                              Trip Reason: {cb.trip_reason}
                            </div>
                          )}
                          <div style={{ marginTop: "6px", display: "flex", justifyContent: "flex-end" }}>
                            <button
                              onClick={() => handleResetCircuitBreakers(cb.session_id)}
                              style={{
                                padding: "4px 8px",
                                background: "transparent",
                                border: "1px solid var(--border-subtle)",
                                borderRadius: "4px",
                                color: "var(--text-muted)",
                                fontSize: "10px",
                                cursor: "pointer",
                              }}
                            >
                              Reset Session Circuit
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}


        </div>
      </div>
    </div>
  );
}