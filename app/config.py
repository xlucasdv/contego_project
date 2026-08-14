from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    otx_api_key: str | None = None
    virustotal_api_key: str | None = None
    default_provider: str = "otx"

    openai_api_key: str | None = None
    openai_model: str = "gpt-4o-mini"

    db_path: str = "threat_lookup.db"


settings = Settings()