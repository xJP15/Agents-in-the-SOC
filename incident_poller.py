"""
Incident Poller for SOC Triage System.
Polls Sentinel for new incidents with deduplication and cursor management.
"""

import json
import logging
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, Callable
from dataclasses import dataclass, field, asdict

from config import load_config, STATE_DIR, SentinelConfig
from sentinel_client import SentinelClient, AuthenticationError, QueryError

logger = logging.getLogger(__name__)


@dataclass
class PollerState:
    """Persistent state for the poller to track progress."""
    last_poll_time: Optional[str] = None  # ISO format
    last_incident_time: Optional[str] = None  # Latest TimeGenerated seen
    seen_incident_ids: list[str] = field(default_factory=list)
    poll_count: int = 0
    error_count: int = 0

    def get_last_incident_datetime(self) -> Optional[datetime]:
        """Get last incident time as datetime object."""
        if self.last_incident_time:
            return datetime.fromisoformat(self.last_incident_time.replace('Z', '+00:00'))
        return None

    def update_with_incidents(self, incidents: list[dict]):
        """Update state with newly fetched incidents."""
        if not incidents:
            return

        # Track seen incident IDs (keep last 1000 to prevent unbounded growth)
        new_ids = [inc.get('IncidentName') or inc.get('SystemAlertId') for inc in incidents]
        self.seen_incident_ids = list(set(self.seen_incident_ids + new_ids))[-1000:]

        # Update last incident time to the most recent
        times = []
        for inc in incidents:
            time_str = inc.get('TimeGenerated')
            if time_str:
                try:
                    dt = datetime.fromisoformat(time_str.replace('Z', '+00:00'))
                    times.append(dt)
                except ValueError:
                    pass

        if times:
            latest = max(times)
            self.last_incident_time = latest.isoformat()

    def is_seen(self, incident: dict) -> bool:
        """Check if an incident has already been processed."""
        incident_id = incident.get('IncidentName') or incident.get('SystemAlertId')
        return incident_id in self.seen_incident_ids


class StateManager:
    """Manages persistent poller state."""

    def __init__(self, state_file: Path = None):
        """
        Initialize state manager.

        Args:
            state_file: Path to state file. Defaults to state/poller_state.json.
        """
        self.state_file = state_file or (STATE_DIR / 'poller_state.json')

    def load(self) -> PollerState:
        """Load state from disk."""
        if not self.state_file.exists():
            logger.info("No existing state file, starting fresh")
            return PollerState()

        try:
            with open(self.state_file, 'r') as f:
                data = json.load(f)
            logger.info(f"Loaded state: poll_count={data.get('poll_count', 0)}")
            return PollerState(**data)
        except (json.JSONDecodeError, TypeError) as e:
            logger.warning(f"Failed to load state file, starting fresh: {e}")
            return PollerState()

    def save(self, state: PollerState):
        """Save state to disk."""
        self.state_file.parent.mkdir(parents=True, exist_ok=True)

        with open(self.state_file, 'w') as f:
            json.dump(asdict(state), f, indent=2, default=str)

        logger.debug(f"Saved state to {self.state_file}")


@dataclass
class NormalizedIncident:
    """Normalized incident format for Langflow processing."""
    id: str
    title: str
    description: str
    severity: str
    status: str
    created_time: str
    source: str
    url: Optional[str] = None
    tactics: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    entities: list[dict] = field(default_factory=list)
    alert_ids: list[str] = field(default_factory=list)
    # NOTE: raw field excluded from output methods to prevent data leakage
    _raw: dict = field(default_factory=dict, repr=False)

    def to_alert_schema(self) -> dict:
        """
        Convert to structured alert schema for RAG/Langflow pipeline.

        This is the primary output format for downstream processing.
        Does NOT include raw event data to prevent sensitive data leakage.
        """
        # Infer alert type from title/description
        alert_type = self._infer_alert_type()

        # Extract key entities in structured format
        extracted_entities = self._extract_entities()

        return {
            "alert_type": alert_type,
            "incident_id": self.id,
            "title": self.title,
            "severity": self.severity.lower(),
            "status": self.status,
            "time_generated": self.created_time,
            "source_provider": self.source,
            "mitre": {
                "tactics": self.tactics,
                "techniques": self.techniques,
            },
            "entities": extracted_entities,
            "description": self.description,
            "incident_url": self.url,
            "related_alert_ids": self.alert_ids,
        }

    def _infer_alert_type(self) -> str:
        """Infer alert type from title/description/tactics/techniques for RAG routing."""
        title_lower = self.title.lower()
        desc_lower = self.description.lower()
        combined = f"{title_lower} {desc_lower}"

        # Also check tactics and techniques
        tactics_str = ' '.join(self.tactics).lower()
        techniques_str = ' '.join(self.techniques).lower()

        # Map to runbook categories - check keywords first
        if any(kw in combined for kw in ['impossible travel', 'atypical', 'unfamiliar location', 'sign-in from', 'risky sign-in']):
            return "impossible_travel"
        elif any(kw in combined for kw in ['mfa', 'multi-factor', 'push', 'fatigue', 'authentication attempt', 'mfa bombing']):
            return "mfa_fatigue"
        elif any(kw in combined for kw in ['oauth', 'consent', 'application consent', 'app permission', 'illicit consent']):
            return "oauth_consent_abuse"
        elif any(kw in combined for kw in ['inbox rule', 'forwarding', 'mail rule', 'mailbox', 'email forwarding']):
            return "mailbox_rule_abuse"
        elif any(kw in combined for kw in ['phish', 'malicious link', 'click', 'url', 'safe links', 'credential harvest']):
            return "phishing_click"
        elif any(kw in combined for kw in ['password spray', 'brute force', 'failed login', 'credential access', 'multiple failed']):
            return "password_spray"

        # Fallback: check MITRE techniques
        if 't1110' in techniques_str:  # Brute Force
            return "password_spray"
        elif 't1566' in techniques_str:  # Phishing
            return "phishing_click"
        elif 't1078' in techniques_str and 'initial' in tactics_str:  # Valid Accounts + Initial Access
            return "impossible_travel"
        elif 't1114' in techniques_str:  # Email Collection
            return "mailbox_rule_abuse"
        elif 't1528' in techniques_str:  # Steal Application Access Token
            return "oauth_consent_abuse"

        # Fallback: check tactics
        if 'credentialaccess' in tactics_str:
            return "password_spray"
        elif 'initialaccess' in tactics_str:
            return "impossible_travel"

        return "unknown"

    def _extract_entities(self) -> dict:
        """Extract and categorize entities from the incident."""
        extracted = {
            "users": [],
            "ips": [],
            "hosts": [],
            "apps": [],
            "urls": [],
            "files": [],
        }

        for entity in self.entities:
            entity_type = entity.get('Type', '').lower()

            if entity_type == 'account':
                upn = entity.get('UserPrincipalName') or entity.get('Name')
                if upn:
                    extracted["users"].append(upn)
            elif entity_type == 'ip':
                addr = entity.get('Address')
                if addr:
                    extracted["ips"].append(addr)
            elif entity_type == 'host':
                hostname = entity.get('HostName') or entity.get('NetBiosName')
                if hostname:
                    extracted["hosts"].append(hostname)
            elif entity_type == 'cloudapplication':
                app_name = entity.get('Name') or entity.get('AppId')
                if app_name:
                    extracted["apps"].append(str(app_name))
            elif entity_type == 'url':
                url = entity.get('Url')
                if url:
                    extracted["urls"].append(url)
            elif entity_type == 'file':
                filename = entity.get('Name')
                if filename:
                    extracted["files"].append(filename)

        # Remove empty lists
        return {k: v for k, v in extracted.items() if v}

    def to_dict(self) -> dict:
        """
        Convert to dictionary for JSON serialization.
        Uses to_alert_schema() to ensure safe output.
        """
        return self.to_alert_schema()

    def __repr__(self) -> str:
        """Safe repr that doesn't expose raw data."""
        return (
            f"NormalizedIncident(id='{self.id}', title='{self.title[:50]}...', "
            f"severity='{self.severity}', status='{self.status}')"
        )


def normalize_incident(raw: dict) -> NormalizedIncident:
    """
    Normalize a raw incident from Sentinel into standard format.

    Args:
        raw: Raw incident dictionary from API.

    Returns:
        NormalizedIncident object.
    """
    # Handle both SecurityIncident and SecurityAlert formats
    incident_id = raw.get('IncidentName') or raw.get('SystemAlertId') or 'unknown'
    title = raw.get('Title') or raw.get('AlertName') or 'Untitled'
    severity = raw.get('Severity') or raw.get('AlertSeverity') or 'Unknown'

    # Parse entities - may be double-encoded JSON from make_set()
    entities = []
    entities_raw = raw.get('Entities')
    if entities_raw:
        def parse_entities_recursive(data):
            """Recursively parse potentially nested JSON strings."""
            result = []
            if isinstance(data, str):
                try:
                    parsed = json.loads(data)
                    result.extend(parse_entities_recursive(parsed))
                except json.JSONDecodeError:
                    pass
            elif isinstance(data, list):
                for item in data:
                    result.extend(parse_entities_recursive(item))
            elif isinstance(data, dict):
                result.append(data)
            return result

        entities = parse_entities_recursive(entities_raw)

    # Parse tactics - may be double-encoded JSON from make_set()
    def parse_string_list(data):
        """Parse potentially nested JSON strings into flat list."""
        result = []
        if isinstance(data, str):
            try:
                parsed = json.loads(data)
                result.extend(parse_string_list(parsed))
            except json.JSONDecodeError:
                # Plain string, might be comma-separated
                result.extend([t.strip() for t in data.split(',') if t.strip()])
        elif isinstance(data, list):
            for item in data:
                result.extend(parse_string_list(item))
        return result

    tactics = []
    tactics_raw = raw.get('Tactics')
    if tactics_raw:
        tactics = parse_string_list(tactics_raw)
    # Deduplicate while preserving order
    tactics = list(dict.fromkeys(tactics))

    # Parse techniques - may be double-encoded JSON from make_set()
    techniques = []
    techniques_raw = raw.get('Techniques')
    if techniques_raw:
        techniques = parse_string_list(techniques_raw)
    # Deduplicate while preserving order
    techniques = list(dict.fromkeys(techniques))

    # Parse alert IDs
    alert_ids = []
    alert_ids_raw = raw.get('AlertIds')
    if alert_ids_raw:
        try:
            if isinstance(alert_ids_raw, str):
                alert_ids = json.loads(alert_ids_raw)
            elif isinstance(alert_ids_raw, list):
                alert_ids = alert_ids_raw
        except json.JSONDecodeError:
            pass

    return NormalizedIncident(
        id=incident_id,
        title=title,
        description=raw.get('Description') or '',
        severity=severity,
        status=raw.get('Status') or 'New',
        created_time=raw.get('TimeGenerated') or raw.get('CreatedTime') or '',
        source=raw.get('ProviderName') or raw.get('VendorName') or 'Sentinel',
        url=raw.get('IncidentUrl'),
        tactics=tactics,
        techniques=techniques,
        entities=entities,
        alert_ids=alert_ids,
        _raw=raw,  # Internal use only; excluded from output methods
    )


class IncidentPoller:
    """
    Polls Sentinel for new incidents with deduplication.

    Features:
    - Persistent cursor tracking
    - Duplicate detection
    - Configurable polling interval
    - Callback for new incidents
    """

    def __init__(
        self,
        config: SentinelConfig,
        on_new_incident: Optional[Callable[[NormalizedIncident], None]] = None,
        state_manager: Optional[StateManager] = None,
    ):
        """
        Initialize the poller.

        Args:
            config: Sentinel configuration.
            on_new_incident: Callback function for each new incident.
            state_manager: Optional custom state manager.
        """
        self.config = config
        self.client = SentinelClient(config)
        self.on_new_incident = on_new_incident
        self.state_manager = state_manager or StateManager()
        self.state = self.state_manager.load()
        self._running = False

    def poll_once(self) -> list[NormalizedIncident]:
        """
        Perform a single poll for new incidents.

        Returns:
            List of new (not previously seen) normalized incidents.
        """
        logger.info("Polling for new incidents...")

        # Determine the time window
        since = self.state.get_last_incident_datetime()

        if since is None:
            # First run: look back based on config
            since = datetime.now(timezone.utc) - timedelta(
                hours=self.config.initial_lookback_hours
            )
            logger.info(f"First poll, looking back {self.config.initial_lookback_hours} hours")

        try:
            # Fetch incidents
            raw_incidents = self.client.get_security_incidents(since=since, limit=100)
            logger.info(f"Fetched {len(raw_incidents)} incidents from API")

            # Also fetch alerts if you want both
            # raw_alerts = self.client.get_security_alerts(since=since, limit=100)

            # Filter out already-seen incidents
            new_incidents = []
            for raw in raw_incidents:
                if not self.state.is_seen(raw):
                    normalized = normalize_incident(raw)
                    new_incidents.append(normalized)

                    # Invoke callback if provided
                    if self.on_new_incident:
                        try:
                            self.on_new_incident(normalized)
                        except Exception as e:
                            logger.error(f"Callback error for incident {normalized.id}: {e}")

            # Update state
            self.state.poll_count += 1
            self.state.last_poll_time = datetime.now(timezone.utc).isoformat()
            self.state.update_with_incidents(raw_incidents)
            self.state_manager.save(self.state)

            logger.info(f"Found {len(new_incidents)} new incidents (filtered from {len(raw_incidents)})")
            return new_incidents

        except (AuthenticationError, QueryError) as e:
            self.state.error_count += 1
            self.state_manager.save(self.state)
            logger.error(f"Poll failed: {e}")
            raise

    def run(self, max_iterations: Optional[int] = None):
        """
        Start continuous polling loop.

        Args:
            max_iterations: Optional limit on number of polls (for testing).
        """
        self._running = True
        iteration = 0

        logger.info(
            f"Starting poller with {self.config.poll_interval_seconds}s interval"
        )

        while self._running:
            try:
                new_incidents = self.poll_once()

                if new_incidents:
                    logger.info(f"Processing {len(new_incidents)} new incidents")
                    for inc in new_incidents:
                        logger.info(f"  [{inc.severity}] {inc.title}")

            except Exception as e:
                logger.error(f"Poll iteration failed: {e}")
                # Continue polling despite errors

            iteration += 1
            if max_iterations and iteration >= max_iterations:
                logger.info(f"Reached max iterations ({max_iterations}), stopping")
                break

            # Wait for next poll
            logger.debug(f"Sleeping {self.config.poll_interval_seconds}s until next poll")
            time.sleep(self.config.poll_interval_seconds)

    def stop(self):
        """Stop the polling loop."""
        logger.info("Stopping poller")
        self._running = False


def example_callback(incident: NormalizedIncident):
    """
    Example callback that logs incident summary.
    NOTE: Only logs metadata, not full content, to prevent data leakage.
    """
    # Log summary only - no sensitive details
    logger.info(
        f"New incident: [{incident.severity}] {incident.id} - "
        f"{incident.title[:60]}{'...' if len(incident.title) > 60 else ''}"
    )

    # Get structured schema for downstream processing
    schema = incident.to_alert_schema()

    # Example: Write to file for Langflow pickup (production would use queue/API)
    # This demonstrates the structured output without logging sensitive data
    logger.debug(f"Alert type inferred: {schema['alert_type']}")


def langflow_triage_callback(incident: NormalizedIncident):
    """
    Callback that sends incidents to Langflow for RAG-based triage.
    Saves triage results to outputs/ directory.
    """
    from langflow_client import (
        LangflowClient,
        load_langflow_config,
        save_triage_result,
    )

    # Log the incident being processed
    logger.info(
        f"Triaging incident: [{incident.severity}] {incident.id} - "
        f"{incident.title[:60]}{'...' if len(incident.title) > 60 else ''}"
    )

    try:
        # Load Langflow config and create client
        lf_config = load_langflow_config()
        client = LangflowClient(lf_config)

        # Get structured alert schema
        alert_data = incident.to_alert_schema()

        # Send to Langflow for triage
        result = client.run_triage(alert_data)

        if result.success:
            # Save the triage result
            filepath = save_triage_result(result)
            logger.info(f"Triage complete: {filepath}")
        else:
            logger.error(f"Triage failed for {incident.id}: {result.error}")

    except ValueError as e:
        logger.error(f"Langflow config error: {e}")
    except Exception as e:
        logger.error(f"Triage error for {incident.id}: {e}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Poll Sentinel for incidents")
    parser.add_argument(
        "--triage",
        action="store_true",
        help="Send incidents to Langflow for triage (requires LANGFLOW_FLOW_ID in .env)",
    )
    parser.add_argument(
        "--continuous",
        action="store_true",
        help="Run continuous polling instead of single poll",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=None,
        help="Max polling iterations (for testing)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    try:
        config = load_config()
        # Config __repr__ already redacts secrets
        logger.info(f"Loaded config: {config}")

        # Choose callback based on --triage flag
        if args.triage:
            logger.info("Triage mode enabled - will send incidents to Langflow")
            callback = langflow_triage_callback
        else:
            callback = example_callback

        # Create poller
        poller = IncidentPoller(
            config=config,
            on_new_incident=callback,
        )

        if args.continuous:
            # Run continuous polling
            logger.info("--- Starting continuous polling ---")
            poller.run(max_iterations=args.max_iterations)
        else:
            # Test single poll
            logger.info("--- Testing single poll ---")
            incidents = poller.poll_once()
            logger.info(f"Retrieved {len(incidents)} new incidents")

            # Show structured schema example (first incident only, if any)
            if incidents:
                schema = incidents[0].to_alert_schema()
                logger.info(f"Example alert_type: {schema['alert_type']}")
                logger.info(f"Example entities: {list(schema.get('entities', {}).keys())}")

    except FileNotFoundError as e:
        logger.error(f"Configuration error: {e}")
    except AuthenticationError as e:
        logger.error(f"Authentication failed: {e}")
    except QueryError as e:
        logger.error(f"Query failed: {e}")
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
