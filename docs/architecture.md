# Initial Architecture

Phase 1 establishes a React/Vite frontend, FastAPI backend, and SQLite database.

- Frontend: `http://localhost:5173`
- Backend: `http://127.0.0.1:8000`
- Health endpoint: `GET /api/health`
- Database: local SQLite file created by the backend at startup.

Claude/Gemini providers, agent tools, attack engine, mitigations and reporting are intentionally deferred to later phases.
