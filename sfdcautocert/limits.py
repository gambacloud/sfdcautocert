"""Resource limits for hosted mode. The service shares a small dyno (and process) with other tools, so a large or
hostile org must not be able to exhaust its memory, threads or outbound connections.
All values can be overridden with environment variables (CERT_MANAGER_*)."""
from __future__ import annotations

import os


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(f"CERT_MANAGER_{name}", default))
    except ValueError:
        return default


MB = 1024 * 1024

MAX_CONCURRENT_SCANS = _int("MAX_CONCURRENT_SCANS", 2)    # process-wide
SCAN_COOLDOWN_S = _int("SCAN_COOLDOWN_S", 30)             # per session, between scan starts
MAX_ENDPOINT_SCANS = _int("MAX_ENDPOINTS", 40)            # TLS probes per scan
MAX_SOAP_RESPONSE = _int("MAX_SOAP_RESPONSE_MB", 40) * MB  # one Metadata API response (base64 zip)
MAX_UNZIPPED = _int("MAX_UNZIPPED_MB", 60) * MB           # one retrieved type, uncompressed
MAX_TOTAL_BLOBS = _int("MAX_TOTAL_MB", 100) * MB          # all retrieved metadata of one scan
MAX_JSON_RESPONSE = _int("MAX_JSON_RESPONSE_MB", 20) * MB  # one Tooling API page
MAX_APEX_SCANNED = _int("MAX_APEX_SCANNED", 5000)          # classes + triggers whose bodies are pulled
MAX_APEX_RETAINED = _int("MAX_APEX_RETAINED_MB", 20) * MB  # bodies kept after filtering
RETRIEVE_WORKERS = _int("RETRIEVE_WORKERS", 3)
