"""
SupplyGraph Backend Configuration
Uses Pydantic Settings v2 for environment variable management.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List
import os


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    All secrets must be provided via environment / .env file.
    NEVER hardcode secrets.
    """
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ============================================================
    # APPLICATION
    # ============================================================
    app_name: str = "SupplyGraph"
    app_version: str = "1.0.0"
    api_version: str = "v1"
    debug: bool = False
    log_level: str = "INFO"

    # ============================================================
    # GITHUB
    # ============================================================
    github_token: str = ""  # Required for GitHub API access

    # ============================================================
    # GEMINI
    # ============================================================
    gemini_api_key: str = ""  # Required for AI explanation layer

    # ============================================================
    # SUPABASE
    # ============================================================
    supabase_url: str = ""
    supabase_anon_key: str = ""
    supabase_service_role_key: str = ""  # BACKEND ONLY - never expose

    # ============================================================
    # CORS
    # ============================================================
    allowed_origins: str = "http://localhost:3000"

    @property
    def origins_list(self) -> List[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]

    # ============================================================
    # ANALYSIS CONFIGURATION
    # ============================================================
    osv_cache_dir: str = ".cache/osv"
    max_repo_size_mb: int = 100
    max_files_per_scan: int = 1000
    max_file_size_kb: int = 500
    analysis_timeout_seconds: int = 300
    max_transitive_depth: int = 10

    # ============================================================
    # CONFIDENCE ENGINE
    # ============================================================
    synthetic_discount: float = 0.15  # Discount for simulated evidence

    # ============================================================
    # BLAST RADIUS WEIGHTS
    # ============================================================
    blast_radius_package_weight: float = 2.0
    blast_radius_service_weight: float = 15.0
    blast_radius_api_weight: float = 25.0
    blast_radius_deployment_weight: float = 50.0

    # ============================================================
    # GRAPH LAYOUT
    # ============================================================
    graph_horizontal_spacing: float = 280.0
    graph_vertical_spacing: float = 120.0

    # ============================================================
    # OSV API
    # ============================================================
    osv_base_url: str = "https://api.osv.dev/v1"
    osv_timeout_seconds: int = 30
    osv_max_retries: int = 3

    # ============================================================
    # TYPOSQUATTING
    # ============================================================
    typosquatting_similarity_threshold: float = 0.85


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """FastAPI dependency for settings injection."""
    return settings
