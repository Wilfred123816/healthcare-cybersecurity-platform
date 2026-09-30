from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from Backend.app.api.routes.events import router as events_router
from Backend.app.api.routes.unified_events import router as unified_events_router
from Backend.app.api.routes.detection import router as detection_router
from Backend.app.api.routes.trust import router as trust_router
from Backend.app.api.routes.trust_aware import router as trust_aware_router
from Backend.app.api.routes import investigation
from Backend.app.api.routes import attack_path
from Backend.app.api.routes import dashboard


app = FastAPI(
    title="Healthcare Cybersecurity Platform",
    description=(
        "AI-powered healthcare cybersecurity and "
        "cyber-resilience platform."
    ),
    version="0.1.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# API ROUTES

# Individual event-source APIs
app.include_router(events_router)
# Unified event API
app.include_router(unified_events_router)
# Detection router API
app.include_router(detection_router)
# Trust evaluation API
app.include_router(trust_router)
# Trust-aware detection API
app.include_router(trust_aware_router)
app.include_router(investigation.router)
app.include_router(attack_path.router)
app.include_router(dashboard.router)
# ROOT ENDPOINT

@app.get("/")
def root():
    return {
        "message": "Healthcare Cybersecurity Platform API",
        "status": "running",
    }
# HEALTH CHECK

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy"
    }