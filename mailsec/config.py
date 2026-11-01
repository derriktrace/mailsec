import hashlib
import ipaddress
import json
import os
from copy import deepcopy
from dataclasses import dataclass, field, fields, replace
from pathlib import Path

import yaml
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
VERSIONS = {"engine": "0.4.0-alpha.8", "parser": "mime-v3.4", "enrichment": "enrichment-v2",
            "evidence": "evidence-v4", "questions": "verdict-v8-action-review-v1", "policy": "protection-v4.1"}


def configuration_snapshot(settings):
    """Detach declared configuration values; runtime Store/lock handles stay local."""
    return replace(settings, **{item.name: deepcopy(getattr(settings, item.name)) for item in fields(settings)})


def secret_value(name):
    """Support container secret files without serializing secrets into reports."""
    filename = os.getenv(name + "_FILE", "")
    return Path(filename).read_text().strip() if filename else os.getenv(name, "")


@dataclass
class Settings:
    database_url: str = field(default="sqlite:///data/mailsec.db", repr=False)
    api_key: str = field(default="", repr=False)
    model: str = "jev-latest"
    decision_provider: str = "jev"
    decision_base_url: str = ""
    decision_api_key: str = field(default="", repr=False)
    decision_timeout_seconds: int = 120
    decision_recipient_address_masking: bool = False
    decision_privacy_authorization: dict = field(default_factory=dict, repr=False)
    decision_configuration_revision: str = ""
    organization: dict = field(default_factory=dict)
    google_service_account_file: str = ""
    mailboxes: list[str] = field(default_factory=list)
    initial_query: str = "-in:sent -in:drafts"
    max_initial_messages: int = 500
    poll_seconds: int = 30
    app_token: str = field(default="", repr=False)
    bind_host: str = "127.0.0.1"
    allowed_hosts: list[str] = field(default_factory=lambda: ["localhost", "127.0.0.1", "[::1]", "testserver"])
    embedded_worker: bool = False
    max_message_bytes: int = 25 * 1024 * 1024
    tenant_id: str = "local"
    google_oauth_client_file: str = ""
    google_oauth_redirect_uri: str = "http://localhost:8025/oauth/google/callback"
    token_encryption_key: str = field(default="", repr=False)
    authorized_mailboxes: list[str] = field(default_factory=list)
    enforcement_mode: str = "passive"
    notifications_enabled: bool = False
    quarantine_threshold: float = .98
    corroboration_threshold: float = .9
    inspection_url: str = ""
    inspection_timeout_seconds: int = 120
    web_risk_api_key: str = field(default="", repr=False)
    url_lookup_monthly_limit: int = 100000
    max_urls_per_message: int = 40
    cache_epoch: str = "1"
    jev_cache_seconds: int = 300
    require_auth: bool = False
    public_base_url: str = ""
    evaluation_mode: bool = False
    workspace_name: str = "Mail workspace"
    evaluation_proxy_url: str = ""
    workspace_switching: bool = False
    action_review_enabled: bool = False
    claim_verification_enabled: bool = False

    def __post_init__(self):
        if self.decision_provider not in {"jev", "ollama", "openai_compatible"}:
            raise ValueError("Decision provider must be jev, ollama, or openai_compatible")
        if self.evaluation_mode:
            self.enforcement_mode = "passive"
            self.notifications_enabled = False
            self.mailboxes = []
            self.authorized_mailboxes = []
            self.google_service_account_file = ""
            self.google_oauth_client_file = ""
            self.token_encryption_key = ""
            self.organization = {}
        if self.enforcement_mode not in {"passive", "flag_only", "auto_quarantine"}:
            raise ValueError("Invalid enforcement mode")
        if not .95 <= self.quarantine_threshold <= 1 or not .8 <= self.corroboration_threshold <= 1:
            raise ValueError("Automatic quarantine thresholds must remain conservative")
        if self.require_auth and len(self.app_token) < 32:
            raise ValueError("A console token of at least 32 characters is required")
        self.validate_bind(self.bind_host)

    def validate_bind(self, host):
        """Direct LAN/public listeners must never start with local-demo security."""
        try:
            loopback = ipaddress.ip_address(host.strip("[]")).is_loopback
        except ValueError:
            loopback = host.lower() == "localhost"
        if not loopback:
            if len(self.app_token) < 32:
                raise ValueError("A non-loopback listener requires a console token of at least 32 characters")
            if not self.allowed_hosts or "*" in self.allowed_hosts:
                raise ValueError("A non-loopback listener requires explicit allowed hostnames")

    @classmethod
    def load(cls):
        # Explicit environment wins. Reuse the already-provided key, never copy it.
        load_dotenv(ROOT / ".env.local")
        load_dotenv(ROOT.parent / ".env.local")
        config_path = Path(os.getenv("MAILSEC_ORG_CONFIG", str(ROOT / "organization.yaml")))
        if not config_path.is_absolute():
            config_path = ROOT / config_path
        organization = yaml.safe_load(config_path.read_text()) if config_path.exists() else {}
        organization = organization or {}
        if not isinstance(organization, dict):
            raise ValueError("Organization configuration must be a mapping")
        organization = organization.get("organization", organization)
        if not isinstance(organization, dict):
            raise ValueError("Organization configuration must be a mapping")
        database_url = secret_value("MAILSEC_DATABASE_URL") or f"sqlite:///{ROOT / 'data/mailsec.db'}"
        if database_url.startswith("sqlite:///"):
            db_path = Path(database_url.removeprefix("sqlite:///"))
            db_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if db_path.parent == ROOT / "data":
                db_path.parent.chmod(0o700)
                if db_path.exists():
                    db_path.chmod(0o600)
        return cls(
            database_url=database_url,
            api_key=secret_value("TYPESAFE_API_KEY"),
            model=os.getenv("TYPESAFE_MODEL", "jev-latest"), organization=organization,
            decision_provider=os.getenv("MAILSEC_DECISION_PROVIDER", "jev"),
            decision_base_url=os.getenv("MAILSEC_DECISION_BASE_URL", ""),
            decision_api_key=secret_value("MAILSEC_DECISION_API_KEY"),
            decision_timeout_seconds=min(300, max(10, int(os.getenv("MAILSEC_DECISION_TIMEOUT_SECONDS", "120")))),
            google_service_account_file=os.getenv("GOOGLE_SERVICE_ACCOUNT_FILE", ""),
            mailboxes=[s.strip() for s in os.getenv("MAILSEC_MAILBOXES", "").split(",") if s.strip()],
            initial_query=os.getenv("MAILSEC_INITIAL_QUERY", "-in:sent -in:drafts"),
            max_initial_messages=int(os.getenv("MAILSEC_MAX_INITIAL_MESSAGES", "500")),
            poll_seconds=max(10, int(os.getenv("MAILSEC_POLL_SECONDS", "30"))),
            app_token=secret_value("MAILSEC_APP_TOKEN"),
            bind_host=os.getenv("MAILSEC_BIND_HOST", "127.0.0.1"),
            allowed_hosts=[host.strip() for host in os.getenv(
                "MAILSEC_ALLOWED_HOSTS", "localhost,127.0.0.1,[::1],testserver").split(",") if host.strip()],
            embedded_worker=os.getenv("MAILSEC_EMBEDDED_WORKER", "false").lower() == "true",
            tenant_id=os.getenv("MAILSEC_TENANT_ID", "local"),
            google_oauth_client_file=os.getenv("GOOGLE_OAUTH_CLIENT_FILE", ""),
            google_oauth_redirect_uri=os.getenv("GOOGLE_OAUTH_REDIRECT_URI", "http://localhost:8025/oauth/google/callback"),
            token_encryption_key=secret_value("MAILSEC_TOKEN_ENCRYPTION_KEY"),
            authorized_mailboxes=[s.strip().lower() for s in os.getenv("MAILSEC_AUTHORIZED_MAILBOXES", "").split(",") if s.strip()],
            enforcement_mode=os.getenv("MAILSEC_ENFORCEMENT_MODE", "passive"),
            notifications_enabled=os.getenv("MAILSEC_NOTIFICATIONS_ENABLED", "false").lower() == "true",
            quarantine_threshold=float(os.getenv("MAILSEC_QUARANTINE_THRESHOLD", ".98")),
            corroboration_threshold=float(os.getenv("MAILSEC_CORROBORATION_THRESHOLD", ".9")),
            inspection_url=os.getenv("MAILSEC_INSPECTION_URL", ""),
            inspection_timeout_seconds=min(120, max(5, int(os.getenv("MAILSEC_INSPECTION_TIMEOUT_SECONDS", "120")))),
            web_risk_api_key=secret_value("WEB_RISK_API_KEY"),
            url_lookup_monthly_limit=max(0, int(os.getenv("MAILSEC_URL_LOOKUP_MONTHLY_LIMIT", "100000"))),
            max_urls_per_message=min(100, max(1, int(os.getenv("MAILSEC_MAX_URLS_PER_MESSAGE", "40")))),
            cache_epoch=os.getenv("MAILSEC_CACHE_EPOCH", "1"),
            jev_cache_seconds=min(900, max(0, int(os.getenv("MAILSEC_JEV_CACHE_SECONDS", "300")))),
            require_auth=os.getenv("MAILSEC_REQUIRE_AUTH", "false").lower() == "true",
            public_base_url=os.getenv("MAILSEC_PUBLIC_BASE_URL", ""),
            evaluation_mode=os.getenv("MAILSEC_EVALUATION_MODE", "false").lower() == "true",
            workspace_name=os.getenv("MAILSEC_WORKSPACE_NAME", "Mail workspace"),
            evaluation_proxy_url=os.getenv("MAILSEC_EVALUATION_PROXY_URL", ""),
            workspace_switching=os.getenv("MAILSEC_WORKSPACE_SWITCHING", "false").lower() == "true",
            action_review_enabled=os.getenv("MAILSEC_ACTION_REVIEW_ENABLED", "false").lower() == "true",
            claim_verification_enabled=os.getenv("MAILSEC_CLAIM_VERIFICATION_ENABLED", "false").lower() == "true",
        )

    def versions(self):
        package = Path(__file__).parent
        source = hashlib.sha256()
        for path in sorted(package.glob("*.py")):
            source.update(path.name.encode() + b"\0" + path.read_bytes())
        return {**VERSIONS, "source_sha256": source.hexdigest(),
                "decision_provider": self.decision_provider,
                "decision_endpoint_sha256": hashlib.sha256(self.decision_base_url.encode()).hexdigest(),
                "questions_sha256": hashlib.sha256((package / "questions.json").read_bytes()).hexdigest(),
                "action_review_enabled": self.action_review_enabled,
                "claim_verification_enabled": self.claim_verification_enabled,
                "action_questions_sha256": hashlib.sha256((package / "action_questions.json").read_bytes()).hexdigest(),
                "authority_questions_sha256": hashlib.sha256((package / "authority_questions.json").read_bytes()).hexdigest(),
                "organization_sha256": hashlib.sha256(
                    json.dumps(self.organization, sort_keys=True).encode()).hexdigest()}
