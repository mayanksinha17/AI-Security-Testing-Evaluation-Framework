from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.health import router as health_router
from app.chatbot.routes import router as chatbot_router
from app.agent import agent_router
from app.attacks import attacks_router
from app.dashboard import dashboard_router
from app.evaluation import evaluation_router
from app.core.config import settings
from app.database.session import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="AI Security Testing & Evaluation Framework",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router)
app.include_router(chatbot_router)
app.include_router(agent_router, prefix="/api")
app.include_router(attacks_router, prefix="/api")
app.include_router(evaluation_router)
app.include_router(dashboard_router)


@app.get("/", tags=["system"])
def root() -> dict[str, str]:
    return {"message": "AI Security POC API is running"}
