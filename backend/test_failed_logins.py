
import os
from datetime import datetime, timezone

import requests

# SEER's local development API.
API_URL = "http://127.0.0.1:8000"

# Use the Organization A admin credentials from your local
# development setup. Avoid putting real production passwords here.
EMAIL = os.getenv("SEER_TEST_EMAIL", "admin@sentinel.local")
PASSWORD = os.getenv("SEER_TEST_PASSWORD")

if not PASSWORD:
    raise SystemExit(
        "Set SEER_TEST_PASSWORD in PowerShell before running this script."
    )

# Sign in and obtain an access token.
login_response = requests.post(
    f"{API_URL}/api/v1/auth/login",
    data={"username": EMAIL, "password": PASSWORD},
    timeout=10,
)
login_response.raise_for_status()
token = login_response.json()["access_token"]

headers = {"Authorization": f"Bearer {token}"}

# Create five recent failed-login events.
for number in range(5):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "wazuh",
        "event_type": "authentication_failure",
        "severity": 5,
        "source_ip": "192.168.1.200",
        "username": "testuser",
        "message": f"SEER automated detection test {number + 1}",
    }

    response = requests.post(
        f"{API_URL}/api/v1/events/",
        json=event,
        headers=headers,
        timeout=10,
    )
    response.raise_for_status()
    print(f"Event {number + 1} stored: {response.json()}")

# Run the detector using the same authenticated organization.
response = requests.post(
    f"{API_URL}/api/v1/detections/failed-logins",
    headers=headers,
    timeout=10,
)
response.raise_for_status()

print("\nDetection response:")
print(response.json())
