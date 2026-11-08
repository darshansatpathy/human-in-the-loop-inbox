from __future__ import annotations

from pathlib import Path

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="HITL_", env_file=".env", extra="ignore")

    database_url: str = "postgresql://postgres@localhost:5432/hitl"
    signing_key: SecretStr = SecretStr("change-me-to-32-random-bytes-in-production")
    public_url: str = "http://127.0.0.1:8000"
    policy_file: Path = Path("policy.yaml")
    grant_ttl_seconds: int = 900
    slack_bot_token: SecretStr | None = None
    slack_signing_secret: SecretStr | None = None
    slack_api_url: str = "https://slack.com/api"
    smtp_host: str | None = None
    smtp_port: int = 25
    email_from: str = "approvals@example.com"
    sweep_interval_seconds: float = 15
    dispatch_interval_seconds: float = 1
