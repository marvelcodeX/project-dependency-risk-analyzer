"""Application configuration.

Settings are read from the environment (or a local ``.env`` file). Defaults are
chosen so the app runs with zero external infrastructure — SQLite for storage —
while allowing a PostgreSQL URL in production.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Async SQLAlchemy URL. SQLite by default; for Postgres use e.g.
    #   postgresql+asyncpg://user:pass@localhost:5432/soteria
    database_url: str = "sqlite+aiosqlite:///./soteria.db"

    # CORS origin for the Vite dev server.
    frontend_origin: str = "http://localhost:5173"

    # CISA Known Exploited Vulnerabilities catalog.
    cisa_kev_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )
    # How long to cache the KEV catalog in memory (seconds).
    kev_cache_ttl: int = 6 * 60 * 60

    # Local LLM (Ollama) for plain-English explanations. Optional — the app
    # runs fine without it; AI features just report "unavailable".
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "mistral"
    # LLM calls are slow; give them a generous timeout.
    ollama_timeout: float = 120.0


settings = Settings()
