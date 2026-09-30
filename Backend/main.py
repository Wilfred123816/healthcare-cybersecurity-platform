from fastapi import FastAPI

from Backend.app.api.routes import events
from Backend.app.api.routes import evidence
from Backend.app.api.routes import unified_events


app = FastAPI(
    title="Healthcare Cybersecurity Platform",
    description="AI-powered healthcare cybersecurity and cyber-resilience platform",
    version="1.0.0"
)

# API ROUTES

# Individual event-source APIs
app.include_router(events.router)

# Security evidence API
app.include_router(evidence.router)

# Unified event API
app.include_router(unified_events.router)
# ROOT ENDPOINT

@app.get("/")
def root():
    return {
        "message": "Healthcare Cybersecurity Platform API",
        "status": "running",
        "version": "1.0.0"
    }

# HEALTH CHECK

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy"
    }