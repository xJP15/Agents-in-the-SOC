"""
Configuration management for SOC Triage System.
Loads settings from environment variables with validation.
"""

import os
from dataclasses import dataclass
from pathlib import Path
from dotenv import load_dotenv


@dataclass
class SentinelConfig:
    """Configuration for Microsoft Sentinel / Log Analytics integration."""
    tenant_id: str
    client_id: str
    client_secret: str
    workspace_id: str
    poll_interval_seconds: int = 60
    initial_lookback_hours: int = 24

    def __post_init__(self):
        """Validate required fields are not empty."""
        required = ['tenant_id', 'client_id', 'client_secret', 'workspace_id']
        for field in required:
            value = getattr(self, field)
            if not value or value.startswith('your-'):
                raise ValueError(
                    f"Missing or invalid {field}. "
                    f"Please set {field.upper().replace('_', '_')} in .env file."
                )

    def __repr__(self):
        """Safe repr that doesn't expose secrets."""
        return (
            f"SentinelConfig(tenant_id='{self.tenant_id[:8]}...', "
            f"client_id='{self.client_id[:8]}...', "
            f"client_secret='[REDACTED]', "
            f"workspace_id='{self.workspace_id[:8]}...')"
        )


def load_config(env_path: Path = None) -> SentinelConfig:
    """
    Load configuration from .env file.

    Args:
        env_path: Optional path to .env file. Defaults to project root.

    Returns:
        SentinelConfig object with validated settings.

    Raises:
        ValueError: If required settings are missing.
        FileNotFoundError: If .env file doesn't exist.
    """
    if env_path is None:
        env_path = Path(__file__).parent / '.env'

    if not env_path.exists():
        raise FileNotFoundError(
            f".env file not found at {env_path}. "
            f"Copy .env.template to .env and fill in your values."
        )

    # Load environment variables from .env
    load_dotenv(env_path)

    return SentinelConfig(
        tenant_id=os.getenv('AZURE_TENANT_ID', ''),
        client_id=os.getenv('AZURE_CLIENT_ID', ''),
        client_secret=os.getenv('AZURE_CLIENT_SECRET', ''),
        workspace_id=os.getenv('LOG_ANALYTICS_WORKSPACE_ID', ''),
        poll_interval_seconds=int(os.getenv('POLL_INTERVAL_SECONDS', '60')),
        initial_lookback_hours=int(os.getenv('INITIAL_LOOKBACK_HOURS', '24')),
    )


# Project paths
PROJECT_ROOT = Path(__file__).parent
STATE_DIR = PROJECT_ROOT / 'state'
KB_DIR = PROJECT_ROOT / 'kb'
OUTPUTS_DIR = PROJECT_ROOT / 'outputs'
CHROMA_DIR = PROJECT_ROOT / 'chroma'

# Ensure directories exist
STATE_DIR.mkdir(exist_ok=True)
