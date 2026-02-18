"""
Microsoft Sentinel / Log Analytics API Client.
Handles authentication and KQL query execution.
"""

import time
import logging
from datetime import datetime, timezone
from typing import Optional
from dataclasses import dataclass

import requests

from config import SentinelConfig

logger = logging.getLogger(__name__)


@dataclass
class TokenCache:
    """Cached access token with expiry tracking."""
    access_token: str
    expires_at: float  # Unix timestamp

    def is_expired(self, buffer_seconds: int = 300) -> bool:
        """Check if token is expired or will expire within buffer."""
        return time.time() >= (self.expires_at - buffer_seconds)

    def __repr__(self) -> str:
        """Safe repr that never exposes the token."""
        remaining = max(0, self.expires_at - time.time())
        return f"TokenCache(access_token='[REDACTED]', expires_in={int(remaining)}s)"


class SentinelClient:
    """
    Client for Microsoft Sentinel / Log Analytics API.

    Handles:
    - OAuth2 client credentials authentication
    - Token caching and refresh
    - KQL query execution
    - Error handling and retries
    """

    TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    QUERY_URL = "https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"
    SCOPE = "https://api.loganalytics.io/.default"

    def __init__(self, config: SentinelConfig):
        """
        Initialize the Sentinel client.

        Args:
            config: SentinelConfig with credentials and settings.
        """
        self.config = config
        self._token_cache: Optional[TokenCache] = None
        self._session = requests.Session()

        # Configure session defaults
        self._session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        })

    def _get_access_token(self) -> str:
        """
        Get a valid access token, refreshing if necessary.

        Returns:
            Valid access token string.

        Raises:
            AuthenticationError: If token acquisition fails.
        """
        # Return cached token if still valid
        if self._token_cache and not self._token_cache.is_expired():
            logger.debug("Using cached access token")
            return self._token_cache.access_token

        logger.info("Acquiring new access token")

        token_url = self.TOKEN_URL.format(tenant_id=self.config.tenant_id)

        payload = {
            'client_id': self.config.client_id,
            'client_secret': self.config.client_secret,
            'scope': self.SCOPE,
            'grant_type': 'client_credentials',
        }

        try:
            # Token endpoint requires form-encoded, not JSON
            response = self._session.post(
                token_url,
                data=payload,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            response.raise_for_status()

            token_data = response.json()

            # Cache the token with expiry
            expires_in = token_data.get('expires_in', 3600)
            self._token_cache = TokenCache(
                access_token=token_data['access_token'],
                expires_at=time.time() + expires_in,
            )

            logger.info(f"Access token acquired, expires in {expires_in} seconds")
            return self._token_cache.access_token

        except requests.exceptions.HTTPError as e:
            error_detail = ""
            try:
                error_detail = e.response.json().get('error_description', '')
            except Exception:
                pass

            raise AuthenticationError(
                f"Failed to acquire access token: {e}. {error_detail}"
            ) from e
        except requests.exceptions.RequestException as e:
            raise AuthenticationError(
                f"Network error during authentication: {e}"
            ) from e

    def execute_query(
        self,
        query: str,
        timespan: Optional[str] = None,
        max_retries: int = 3,
    ) -> list[dict]:
        """
        Execute a KQL query against Log Analytics.

        Args:
            query: KQL query string.
            timespan: Optional ISO 8601 duration (e.g., 'PT1H' for 1 hour).
            max_retries: Number of retry attempts on transient failures.

        Returns:
            List of result rows as dictionaries.

        Raises:
            QueryError: If query execution fails.
            AuthenticationError: If authentication fails.
        """
        query_url = self.QUERY_URL.format(workspace_id=self.config.workspace_id)

        payload = {'query': query}
        if timespan:
            payload['timespan'] = timespan

        for attempt in range(max_retries):
            try:
                token = self._get_access_token()

                headers = {'Authorization': f'Bearer {token}'}

                response = self._session.post(
                    query_url,
                    json=payload,
                    headers=headers,
                    timeout=120,
                )

                # Handle specific error codes
                if response.status_code == 401:
                    # Token might be invalid, clear cache and retry
                    logger.warning("Received 401, clearing token cache")
                    self._token_cache = None
                    continue

                if response.status_code == 429:
                    # Rate limited, wait and retry
                    retry_after = int(response.headers.get('Retry-After', 30))
                    logger.warning(f"Rate limited, waiting {retry_after} seconds")
                    time.sleep(retry_after)
                    continue

                response.raise_for_status()

                return self._parse_response(response.json())

            except requests.exceptions.HTTPError as e:
                if attempt == max_retries - 1:
                    error_detail = ""
                    try:
                        error_detail = e.response.json()
                    except Exception:
                        pass
                    raise QueryError(
                        f"Query failed after {max_retries} attempts: {e}. {error_detail}"
                    ) from e
                logger.warning(f"Query attempt {attempt + 1} failed: {e}")
                time.sleep(2 ** attempt)  # Exponential backoff

            except requests.exceptions.RequestException as e:
                if attempt == max_retries - 1:
                    raise QueryError(f"Network error: {e}") from e
                logger.warning(f"Network error on attempt {attempt + 1}: {e}")
                time.sleep(2 ** attempt)

        raise QueryError("Query failed after all retry attempts")

    def _parse_response(self, response_data: dict) -> list[dict]:
        """
        Parse Log Analytics API response into list of dictionaries.

        Args:
            response_data: Raw API response.

        Returns:
            List of result rows as dictionaries.
        """
        tables = response_data.get('tables', [])
        if not tables:
            return []

        # Get the first table (primary results)
        table = tables[0]
        columns = [col['name'] for col in table.get('columns', [])]
        rows = table.get('rows', [])

        # Convert to list of dicts
        return [dict(zip(columns, row)) for row in rows]

    def get_security_incidents(
        self,
        since: Optional[datetime] = None,
        limit: int = 100,
    ) -> list[dict]:
        """
        Query SecurityIncident table for recent incidents.

        Args:
            since: Only return incidents created after this time.
            limit: Maximum number of incidents to return.

        Returns:
            List of incident records.
        """
        # Build KQL query
        query_parts = [
            "SecurityIncident",
            "| where Status != 'Closed'",  # Focus on active incidents
        ]

        if since:
            # Format datetime for KQL
            since_str = since.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
            query_parts.append(f"| where TimeGenerated > datetime({since_str})")

        query_parts.extend([
            "| order by TimeGenerated desc",
            f"| take {limit}",
            "| project TimeGenerated, IncidentNumber, Title, Description, Severity,",
            "    Status, Classification, Owner, IncidentUrl, AlertIds,",
            "    ProviderName, CreatedTime, LastModifiedTime, IncidentName",
        ])

        query = "\n".join(query_parts)
        logger.debug(f"Executing query: {query}")

        return self.execute_query(query)

    def get_security_alerts(
        self,
        since: Optional[datetime] = None,
        limit: int = 100,
    ) -> list[dict]:
        """
        Query SecurityAlert table for recent alerts.

        Args:
            since: Only return alerts generated after this time.
            limit: Maximum number of alerts to return.

        Returns:
            List of alert records.
        """
        query_parts = [
            "SecurityAlert",
        ]

        if since:
            since_str = since.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
            query_parts.append(f"| where TimeGenerated > datetime({since_str})")

        query_parts.extend([
            "| order by TimeGenerated desc",
            f"| take {limit}",
            "| project TimeGenerated, AlertName, AlertSeverity, Description,",
            "    ProviderName, VendorName, Status, Tactics, Techniques,",
            "    Entities, SystemAlertId, ConfidenceLevel, CompromisedEntity",
        ])

        query = "\n".join(query_parts)
        logger.debug(f"Executing query: {query}")

        return self.execute_query(query)

    def test_connection(self) -> bool:
        """
        Test the connection to Log Analytics.

        Returns:
            True if connection successful.

        Raises:
            AuthenticationError: If authentication fails.
            QueryError: If query fails.
        """
        logger.info("Testing connection to Log Analytics...")

        # Simple query to verify connectivity
        result = self.execute_query("SecurityIncident | take 1 | project IncidentNumber")

        logger.info("Connection test successful")
        return True


class AuthenticationError(Exception):
    """Raised when authentication to Azure AD fails."""
    pass


class QueryError(Exception):
    """Raised when a Log Analytics query fails."""
    pass


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    from config import load_config

    try:
        config = load_config()
        print(f"Loaded config: {config}")

        client = SentinelClient(config)
        client.test_connection()

        # Get recent incidents
        incidents = client.get_security_incidents(limit=5)
        print(f"\nFound {len(incidents)} recent incidents:")
        for inc in incidents:
            print(f"  - [{inc.get('Severity')}] {inc.get('Title')}")

    except FileNotFoundError as e:
        print(f"Configuration error: {e}")
    except AuthenticationError as e:
        print(f"Authentication failed: {e}")
    except QueryError as e:
        print(f"Query failed: {e}")
