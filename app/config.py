from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OPSPILOT_", env_file=".env", extra="ignore")

    # repr=False keeps secrets out of tracebacks, test failures and logs that print the settings object.
    database_url: str = Field(default="postgresql+psycopg://opspilot:opspilot@localhost:5433/opspilot", repr=False)
    environment: str = "development"
    # Origins allowed to make unsafe (state-changing) requests with a session cookie.
    allowed_origins: list[str] = ["http://localhost:3000"]
    session_ttl_hours: int = 12
    # How long invitation and password-reset links stay valid.
    invite_ttl_hours: int = 168
    reset_ttl_minutes: int = 120
    # Sign-in throttle: this many failures within the window blocks that email+IP until the window passes.
    login_max_failures: int = 5
    login_window_seconds: int = 900
    cookie_secure: bool = True
    # GitHub (MVP uses a fine-scoped token; a GitHub App replaces this later).
    # Fernet key used to encrypt per-workspace integration tokens at rest. Generate:
    #   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    secret_key: str = Field(default="", repr=False)
    # Dev-only fallback when a workspace has no token of its own.
    github_token: str = Field(default="", repr=False)
    github_api_url: str = "https://api.github.com"
    github_webhook_secret: str = Field(default="", repr=False)
    sync_min_interval_seconds: int = 15
    # AI investigations (Groq, OpenAI-compatible API). Logs are redacted and trimmed before they are sent.
    groq_api_key: str = Field(default="", repr=False)
    groq_model: str = "openai/gpt-oss-120b"  # must be one the key can use: GET https://api.groq.com/openai/v1/models
    ai_max_log_chars: int = 12_000
    ai_investigations_per_minute: int = 5  # per person
    ai_max_code_chars: int = 30_000  # source code the fix agent may send to the model per proposal
    ai_fix_proposals_per_hour: int = 10  # per person


    def production_problems(self) -> list[str]:
        """Settings that are fine on a laptop but unsafe in production. Empty list = ready."""
        problems: list[str] = []
        if "localhost" in self.database_url or "127.0.0.1" in self.database_url:
            problems.append("OPSPILOT_DATABASE_URL points at localhost")
        if not self.secret_key:
            problems.append("OPSPILOT_SECRET_KEY is not set (integration tokens cannot be stored encrypted)")
        if not self.cookie_secure:
            problems.append("OPSPILOT_COOKIE_SECURE is false (session cookies would travel over plain HTTP)")
        if not self.allowed_origins or any("localhost" in o or "127.0.0.1" in o for o in self.allowed_origins):
            problems.append("OPSPILOT_ALLOWED_ORIGINS is empty or contains localhost")
        return problems


def get_settings() -> Settings:
    return Settings()
