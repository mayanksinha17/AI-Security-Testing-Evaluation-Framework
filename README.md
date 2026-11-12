# AI Security POC

Phase 1 foundation for the AI Security Testing & Evaluation Framework.

## Requirements
- Python 3.13 recommended
- Node.js 24 LTS recommended (Vite requires Node.js 20.19+ or 22.12+)
- npm

## Backend (Windows PowerShell)
```powershell
cd backend
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item ..\.env.example ..\.env
uvicorn app.main:app --reload
```
Backend: http://127.0.0.1:8000
Health: http://127.0.0.1:8000/api/health
API docs: http://127.0.0.1:8000/docs

If `py -3.13` is unavailable, use `python -m venv .venv` after installing Python 3.13 and ensuring it is on PATH.

## Frontend (second terminal)
```powershell
cd frontend
npm install
npm run dev
```
Frontend: http://localhost:5173

## Phase 1 verification
1. Backend starts without errors.
2. `GET /api/health` returns `{"status":"ok", ...}`.
3. SQLite database file is created in `backend/` after startup.
4. Frontend displays the AI Security POC Phase 1 starter screen.
5. `npm run build` completes successfully.

No API keys are needed in Phase 1. Do not commit `.env`.
