import os
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()

@dataclass(frozen=True)
class Settings:
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./sentinel.db")
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")
    gemini_model: str = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    enable_ai: bool = os.getenv("ENABLE_AI_ANALYSIS", "false").lower() == "true"
    enable_ml: bool = os.getenv("ENABLE_ML_ANOMALY_DETECTION", "false").lower() == "true"
    intel_provider: str = os.getenv("THREAT_INTEL_PROVIDER", "")
    intel_api_key: str = os.getenv("THREAT_INTEL_API_KEY", "")
    max_upload_bytes: int = int(os.getenv("MAX_UPLOAD_BYTES", "5000000"))
    max_events: int = int(os.getenv("MAX_EVENTS_PER_DATASET", "20000"))
    max_job_seconds: int = int(os.getenv("MAX_JOB_DURATION_SECONDS", "120"))
    cors_origins: str = os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:5173")
settings = Settings()
