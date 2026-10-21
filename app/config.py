from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OPSPILOT_", env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://opspilot:opspilot@localhost:5432/opspilot"
    environment: str = "development"


def get_settings() -> Settings:
    return Settings()
