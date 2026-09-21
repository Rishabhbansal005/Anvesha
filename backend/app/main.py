"""
FastAPI application entrypoint for PROJECT_NAME.
SIH 2026 Problem Statement SIH26106
"""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.api.v1.api import api_router
from app.database.session import engine
from app.database.base import Base
import app.models # Register all models with Base.metadata

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PROJECT_NAME")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables on startup
    try:
        logger.info("[STARTUP] Creating PostgreSQL/SQLite database tables...")
        Base.metadata.create_all(bind=engine)
        logger.info("[STARTUP] Database tables verified successfully.")
    except Exception as e:
        logger.error(f"[STARTUP] Error creating database tables: {e}")
    yield
    logger.info("[SHUTDOWN] Application shutting down.")


app = FastAPI(
    title=settings.PROJECT_NAME,
    description=f"{settings.PROJECT_SUBTITLE} (SIH 2026 - {settings.PROBLEM_STATEMENT})",
    version=settings.VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response
from fastapi import Request, HTTPException

# Security Headers Middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "img-src 'self' data: https:; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "font-src 'self' data:; "
            "connect-src 'self' http: https:;"
        )
        return response

app.add_middleware(SecurityHeadersMiddleware)

# CORS Middleware for Web (Vite) and Mobile (Expo)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Global production-safe exception handler (Prevents stack trace / path leakage)
@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    if isinstance(exc, HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers=getattr(exc, "headers", None)
        )
    logger.error(f"[SECURITY_ERROR] Unhandled exception on {request.method} {request.url.path}: {exc}", exc_info=True)
    if settings.ENVIRONMENT.lower() == "production":
        return JSONResponse(
            status_code=500,
            content={"detail": "An internal error occurred while processing the forensic request."}
        )
    # Mask system filesystem paths and secrets from development error responses
    err_str = str(exc)
    if "C:\\" in err_str or "/Users/" in err_str or "sb_secret" in err_str:
        err_str = "Internal processing error (sensitive system details redacted)."
    return JSONResponse(
        status_code=500,
        content={"detail": err_str}
    )

# Mount API v1 routes
app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/", summary="Root API Gateway Info")
def root():
    return {
        "project": settings.PROJECT_NAME,
        "subtitle": settings.PROJECT_SUBTITLE,
        "problem_statement": settings.PROBLEM_STATEMENT,
        "status": "OPERATIONAL",
        "docs_url": "/docs",
        "api_v1_prefix": settings.API_V1_STR,
        "architecture": "MODULAR_MONOLITH"
    }
