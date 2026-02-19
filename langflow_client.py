"""
Langflow API Client for SOC Triage System.
Sends normalized incidents to Langflow for RAG-based triage.
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Optional
from dataclasses import dataclass

import requests

from config import OUTPUTS_DIR

logger = logging.getLogger(__name__)


@dataclass
class LangflowConfig:
    """Configuration for Langflow API."""
    base_url: str = "http://127.0.0.1:7860"
    flow_id: str = ""
    api_key: Optional[str] = None
    timeout: int = 120

    def __post_init__(self):
        if not self.flow_id:
            raise ValueError(
                "flow_id is required. Get it from Langflow UI (flow settings or URL)"
            )


@dataclass
class TriageResult:
    """Result from Langflow triage."""
    incident_id: str
    alert_type: str
    triage_output: str
    success: bool
    error: Optional[str] = None
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat() + "Z"


class LangflowClient:
    """
    Client for Langflow REST API.

    Sends incidents to a Langflow flow for RAG-based triage
    and returns the model's response.
    """

    def __init__(self, config: LangflowConfig):
        """
        Initialize the Langflow client.

        Args:
            config: LangflowConfig with connection settings.
        """
        self.config = config
        self._session = requests.Session()

        # Set up headers
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }
        if config.api_key:
            headers['x-api-key'] = config.api_key

        self._session.headers.update(headers)

    def run_triage(self, alert_data: dict) -> TriageResult:
        """
        Send an alert to Langflow for triage.

        Args:
            alert_data: Normalized alert dictionary (from NormalizedIncident.to_alert_schema())

        Returns:
            TriageResult with the model's output.
        """
        incident_id = alert_data.get('incident_id', 'unknown')
        alert_type = alert_data.get('alert_type', 'unknown')

        logger.info(f"Sending incident {incident_id} to Langflow for triage")

        # Build the API URL
        url = f"{self.config.base_url}/api/v1/run/{self.config.flow_id}?stream=false"

        # Langflow expects the input as JSON string in the "Alerts JSON" component
        # The tweaks dict maps component names to their input values
        payload = {
            "input_value": json.dumps(alert_data, indent=2),
            "output_type": "text",
            "input_type": "text",
        }

        try:
            response = self._session.post(
                url,
                json=payload,
                timeout=self.config.timeout,
            )

            if response.status_code == 403:
                return TriageResult(
                    incident_id=incident_id,
                    alert_type=alert_type,
                    triage_output="",
                    success=False,
                    error="403 Forbidden - Check Langflow API key or set LANGFLOW_SKIP_AUTH_AUTO_LOGIN=true",
                )

            response.raise_for_status()

            # Parse the response
            result = response.json()

            # Extract the text output from Langflow response
            # Response structure: {"outputs": [{"outputs": [{"results": {"message": {"text": "..."}}}]}]}
            triage_text = self._extract_output(result)

            logger.info(f"Triage complete for incident {incident_id}")

            return TriageResult(
                incident_id=incident_id,
                alert_type=alert_type,
                triage_output=triage_text,
                success=True,
            )

        except requests.exceptions.ConnectionError:
            error = "Cannot connect to Langflow. Is it running on http://127.0.0.1:7860?"
            logger.error(error)
            return TriageResult(
                incident_id=incident_id,
                alert_type=alert_type,
                triage_output="",
                success=False,
                error=error,
            )
        except requests.exceptions.Timeout:
            error = f"Langflow request timed out after {self.config.timeout}s"
            logger.error(error)
            return TriageResult(
                incident_id=incident_id,
                alert_type=alert_type,
                triage_output="",
                success=False,
                error=error,
            )
        except requests.exceptions.HTTPError as e:
            error = f"Langflow API error: {e}"
            logger.error(error)
            return TriageResult(
                incident_id=incident_id,
                alert_type=alert_type,
                triage_output="",
                success=False,
                error=error,
            )
        except Exception as e:
            error = f"Unexpected error: {e}"
            logger.error(error)
            return TriageResult(
                incident_id=incident_id,
                alert_type=alert_type,
                triage_output="",
                success=False,
                error=error,
            )

    def _extract_output(self, response: dict) -> str:
        """
        Extract the text output from Langflow API response.

        Langflow response structure varies, so we try multiple paths.
        """
        try:
            outputs = response.get('outputs', [])
            if outputs:
                first_output = outputs[0]
                inner_outputs = first_output.get('outputs', [])
                if inner_outputs:
                    results = inner_outputs[0].get('results', {})

                    # Path 1: TextOutput component (text.text or text.data.text)
                    text_result = results.get('text', {})
                    if isinstance(text_result, dict):
                        # Try direct text field
                        if 'text' in text_result:
                            return text_result['text']
                        # Try nested data.text
                        if 'data' in text_result and 'text' in text_result['data']:
                            return text_result['data']['text']

                    # Path 2: ChatOutput component (message.text)
                    message = results.get('message', {})
                    if isinstance(message, dict):
                        if 'text' in message:
                            return message['text']
                        if 'data' in message and 'text' in message['data']:
                            return message['data']['text']

                    # Path 3: Direct text in results
                    if 'text' in results:
                        return str(results['text'])

            # Fallback: try to get any text field
            if 'result' in response:
                return str(response['result'])

            # Last resort: return the whole response as string
            return json.dumps(response, indent=2)

        except Exception as e:
            logger.warning(f"Failed to extract output: {e}")
            return json.dumps(response, indent=2)

    def test_connection(self) -> bool:
        """
        Test connection to Langflow.

        Returns:
            True if Langflow is reachable.
        """
        try:
            response = self._session.get(
                f"{self.config.base_url}/health",
                timeout=10,
            )
            return response.status_code == 200
        except Exception:
            return False


def save_triage_result(result: TriageResult, output_dir: Path = None):
    """
    Save triage result to file.

    Args:
        result: TriageResult to save.
        output_dir: Directory for output files. Defaults to outputs/.
    """
    output_dir = output_dir or OUTPUTS_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    # Create filename with timestamp and incident ID
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe_id = result.incident_id.replace('/', '_').replace('\\', '_')[:50]
    filename = f"triage_{timestamp}_{safe_id}.md"

    filepath = output_dir / filename

    # Build the output content
    content = f"""# Triage Report

**Incident ID:** {result.incident_id}
**Alert Type:** {result.alert_type}
**Timestamp:** {result.timestamp}
**Status:** {"Success" if result.success else "Failed"}

---

## Triage Output

{result.triage_output if result.success else f"Error: {result.error}"}
"""

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

    logger.info(f"Saved triage result to {filepath}")
    return filepath


def load_langflow_config() -> LangflowConfig:
    """
    Load Langflow configuration from environment variables.

    Environment variables:
        LANGFLOW_BASE_URL: Langflow server URL (default: http://127.0.0.1:7860)
        LANGFLOW_FLOW_ID: Flow ID to run (required)
        LANGFLOW_API_KEY: API key for authentication (optional)
    """
    from dotenv import load_dotenv
    load_dotenv()

    flow_id = os.getenv('LANGFLOW_FLOW_ID', '')

    return LangflowConfig(
        base_url=os.getenv('LANGFLOW_BASE_URL', 'http://127.0.0.1:7860'),
        flow_id=flow_id,
        api_key=os.getenv('LANGFLOW_API_KEY'),
    )


# Example usage and testing
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Test with a sample alert
    sample_alert = {
        "alert_type": "password_spray",
        "incident_id": "test-001",
        "title": "Potential Password Spray Attack",
        "severity": "medium",
        "status": "New",
        "time_generated": "2026-02-18T12:00:00Z",
        "source_provider": "Azure Sentinel",
        "mitre": {
            "tactics": ["CredentialAccess"],
            "techniques": ["T1110.003"],
        },
        "entities": {
            "users": ["testuser@contoso.com"],
            "ips": ["203.0.113.50"],
        },
        "description": "Multiple failed login attempts detected from single IP address targeting multiple accounts.",
    }

    try:
        config = load_langflow_config()
        print(f"Langflow URL: {config.base_url}")
        print(f"Flow ID: {config.flow_id}")

        client = LangflowClient(config)

        # Test connection
        if client.test_connection():
            print("Langflow is reachable")
        else:
            print("Warning: Cannot reach Langflow health endpoint")

        # Run triage
        print("\nSending test alert for triage...")
        result = client.run_triage(sample_alert)

        if result.success:
            print(f"\nTriage successful!")
            print("-" * 50)
            print(result.triage_output)
            print("-" * 50)

            # Save result
            filepath = save_triage_result(result)
            print(f"\nSaved to: {filepath}")
        else:
            print(f"\nTriage failed: {result.error}")

    except ValueError as e:
        print(f"Configuration error: {e}")
        print("\nMake sure LANGFLOW_FLOW_ID is set in your .env file")
        print("Get the flow ID from Langflow UI (click on flow settings or check the URL)")
