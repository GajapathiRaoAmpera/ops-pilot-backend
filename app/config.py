from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OPSPILOT_", env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://opspilot:opspilot@localhost:5433/opspilot"
    environment: str = "development"
    # Origins allowed to make unsafe (state-changing) requests with a session cookie.
    allowed_origins: list[str] = ["http://localhost:3000"]
    session_ttl_hours: int = 12
    # Sign-in throttle: this many failures within the window blocks that email+IP until the window passes.
    login_max_failures: int = 5
    login_window_seconds: int = 900
    cookie_secure: bool = True
    # GitHub (MVP uses a fine-scoped token; a GitHub App replaces this later).
    github_token: str = ""
    github_api_url: str = "https://api.github.com"
    github_webhook_secret: str = ""
    sync_min_interval_seconds: int = 15


def get_settings() -> Settings:
    return Settings()
