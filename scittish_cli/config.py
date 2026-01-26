"""Configuration management for scittish-cli."""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import httpx


def get_config_dir() -> Path:
    """Get the XDG config directory for scittish."""
    xdg_config = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
    return Path(xdg_config) / "scittish"


def get_config_path() -> Path:
    """Get the path to the global config file."""
    return get_config_dir() / "config.json"


def get_local_config_path() -> Path:
    """Get the path to the local .scittish file."""
    return Path.cwd() / ".scittish"


@dataclass
class GlobalConfig:
    """Global configuration stored in ~/.config/scittish/config.json."""

    server_uri: str = ""
    scitt_url: str = ""
    certificate_chain: str = ""

    def save(self) -> None:
        """Save configuration to disk."""
        config_path = get_config_path()
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(
            json.dumps(
                {
                    "server_uri": self.server_uri,
                    "scitt_url": self.scitt_url,
                    "certificate_chain": self.certificate_chain,
                },
                indent=2,
            )
        )

    @classmethod
    def load(cls) -> "GlobalConfig":
        """Load configuration from disk."""
        config_path = get_config_path()
        if not config_path.exists():
            return cls()
        try:
            data = json.loads(config_path.read_text())
            return cls(
                server_uri=data.get("server_uri", ""),
                scitt_url=data.get("scitt_url", ""),
                certificate_chain=data.get("certificate_chain", ""),
            )
        except (json.JSONDecodeError, KeyError):
            return cls()


@dataclass
class LocalConfig:
    """Local configuration stored in .scittish file in current directory."""

    subject: str = ""

    def save(self) -> None:
        """Save configuration to disk."""
        config_path = get_local_config_path()
        config_path.write_text(
            json.dumps(
                {
                    "subject": self.subject,
                },
                indent=2,
            )
        )

    @classmethod
    def load(cls) -> "LocalConfig":
        """Load configuration from disk."""
        config_path = get_local_config_path()
        if not config_path.exists():
            return cls()
        try:
            data = json.loads(config_path.read_text())
            return cls(
                subject=data.get("subject", ""),
            )
        except (json.JSONDecodeError, KeyError):
            return cls()


def fetch_server_properties(server_uri: str) -> dict:
    """Fetch /properties from the scittish server."""
    url = server_uri.rstrip("/") + "/properties"
    try:
        response = httpx.get(url, timeout=30.0)
        response.raise_for_status()
        return response.json()
    except httpx.HTTPError as e:
        raise RuntimeError(f"Failed to fetch server properties: {e}")


def set_server(server_uri: str) -> GlobalConfig:
    """
    Set the scittish server URI.
    
    Fetches /properties to get ledger URL and certificate chain.
    """
    print(f"Fetching properties from {server_uri}...")
    properties = fetch_server_properties(server_uri)

    config = GlobalConfig(
        server_uri=server_uri,
        scitt_url=properties.get("scitt_url", ""),
        certificate_chain=properties.get("certificate_chain", ""),
    )
    config.save()

    print(f"Server configured successfully.")
    print(f"  Server URI: {config.server_uri}")
    print(f"  SCITT Ledger URL: {config.scitt_url}")
    if config.certificate_chain:
        chain_lines = config.certificate_chain.count("-----BEGIN CERTIFICATE-----")
        print(f"  Certificate chain: {chain_lines} certificate(s)")

    return config


def set_subject(subject: str) -> LocalConfig:
    """Set the subject in the local .scittish file."""
    config = LocalConfig(subject=subject)
    config.save()
    print(f"Subject set to: {subject!r}")
    return config


def get_effective_subject(explicit_subject: Optional[str] = None) -> Optional[str]:
    """
    Get the effective subject based on precedence rules.
    
    Args:
        explicit_subject: Explicitly provided subject (from --subject flag).
                         Empty string means explicitly blank (server resolves).
                         None means not provided.
    
    Returns:
        The effective subject string, or None if not set.
    """
    if explicit_subject is not None:
        # Explicit --subject was provided (even if empty)
        return explicit_subject if explicit_subject else None

    # Fall back to .scittish file
    local_config = LocalConfig.load()
    return local_config.subject if local_config.subject else None
