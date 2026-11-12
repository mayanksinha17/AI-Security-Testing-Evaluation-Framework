import { useEffect, useState } from "react";

const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000";

export default function App() {
  const [health, setHealth] = useState("Checking backend...");
  const [checkedAt, setCheckedAt] = useState("");

  useEffect(() => {
    let active = true;

    fetch(`${API_BASE}/api/health`)
      .then((response) => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then((data) => {
        if (!active) return;
        setHealth(data.status === "ok" ? "Backend connected" : "Unexpected response");
        setCheckedAt(new Date(data.timestamp).toLocaleString());
      })
      .catch(() => {
        if (active) setHealth("Backend not reachable — start FastAPI on port 8000");
      });

    return () => {
      active = false;
    };
  }, []);

  return (
    <main className="shell">
      <nav className="topbar">
        <div className="brand-mark">A</div>
        <span>AI SECURITY <b>LAB</b></span>
        <span className="phase-tag">PHASE 01</span>
      </nav>

      <section className="hero">
        <p className="eyebrow">AI SECURITY TESTING & EVALUATION FRAMEWORK</p>
        <h1>Build. Test. <span>Secure.</span></h1>
        <p className="intro">
          A controlled laboratory for evaluating LLM and Agentic AI security
          across Claude and Gemini.
        </p>

        <div className="status-card">
          <div>
            <p className="card-label">BACKEND STATUS</p>
            <h2>{health}</h2>
            {checkedAt && <p className="muted">Last checked: {checkedAt}</p>}
          </div>
          <span className={`status-dot ${health === "Backend connected" ? "online" : ""}`} />
        </div>
      </section>

      <section className="grid">
        <article className="feature-card">
          <span className="number">01</span>
          <h3>LLM Security</h3>
          <p>Evaluate prompt handling, sensitive information exposure and output safety.</p>
          <span className="coming">FOUNDATION READY</span>
        </article>
        <article className="feature-card">
          <span className="number">02</span>
          <h3>Agentic Security</h3>
          <p>Assess controlled tool use, permissions, execution and memory boundaries.</p>
          <span className="coming">COMING IN PHASE 3</span>
        </article>
        <article className="feature-card">
          <span className="number">03</span>
          <h3>Model Evaluation</h3>
          <p>Compare baseline and mitigated outcomes using reproducible test cases.</p>
          <span className="coming">COMING IN PHASE 7</span>
        </article>
      </section>

      <footer>AI Security POC · Local development environment · No API keys required</footer>
    </main>
  );
}
