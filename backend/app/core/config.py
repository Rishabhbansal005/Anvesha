"""
Core application settings and configuration for ANVESH.
"""
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../.env", "backend/.env"),
        case_sensitive=True,
        extra="ignore"
    )

    PROJECT_NAME: str = "ANVESH"
    PROJECT_SUBTITLE: str = "Email Threat Detection & Forensic Intelligence"
    PROBLEM_STATEMENT: str = "SIH26106"
    VERSION: str = "2.0.0-workspace"
    API_V1_STR: str = "/api/v1"
    
    # Environment
    ENVIRONMENT: str = Field(default="development", env="ENVIRONMENT")
    DEBUG: bool = True
    
    # Supabase Platform Configuration (Values strictly sourced from environment)
    SUPABASE_URL: str = Field(
        default="https://xqqwkcyqllocbagbcdfi.supabase.co",
        env="SUPABASE_URL"
    )
    SUPABASE_SECRET_KEY: str = Field(
        default="",
        env="SUPABASE_SECRET_KEY"
    )
    SUPABASE_PUBLISHABLE_KEY: str = Field(
        default="",
        env="SUPABASE_PUBLISHABLE_KEY"
    )
    
    # Database Configuration (PostgreSQL / SQLite fallback for local developer machines)
    DATABASE_URL: str = Field(
        default="sqlite:///./anvesh_dev.db",
        env="DATABASE_URL"
    )
    SQLITE_FALLBACK_URL: str = "sqlite:///./anvesh_dev.db"
    
    # CORS Origins (Configured allowed origins only; no wildcard allowed when credentials=True)
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://localhost:8081",
        "http://localhost:19000",
        "http://localhost:19006"
    ]
    
    # External Enrichment & Services
    VIRUSTOTAL_API_KEY: str = Field(default="", env="VIRUSTOTAL_API_KEY")
    ABUSEIPDB_API_KEY: str = Field(default="", env="ABUSEIPDB_API_KEY")
    SAFE_BROWSING_API_KEY: str = Field(default="", env="SAFE_BROWSING_API_KEY")
    FCM_SERVER_KEY: str = Field(default="", env="FCM_SERVER_KEY")


settings = Settings()
