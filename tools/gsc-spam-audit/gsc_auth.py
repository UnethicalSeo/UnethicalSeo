"""OAuth helpers for the Search Console API.

Two ways to get credentials, in priority order:

1. Environment variables (headless / CI / remote agent):
       GSC_CLIENT_ID, GSC_CLIENT_SECRET, GSC_REFRESH_TOKEN
   Nothing touches the disk and no browser is needed.

2. A local OAuth client secrets file (first run, on your own machine):
       python gsc_auth.py --client-secrets client_secret.json
   Opens a browser once, writes token.json next to the script, and prints
   the refresh token so you can move it to a secret store later.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

SCOPES = ["https://www.googleapis.com/auth/webmasters.readonly"]
TOKEN_URI = "https://oauth2.googleapis.com/token"
DEFAULT_TOKEN_PATH = Path(__file__).with_name("token.json")


def _from_env() -> Credentials | None:
    client_id = os.environ.get("GSC_CLIENT_ID")
    client_secret = os.environ.get("GSC_CLIENT_SECRET")
    refresh_token = os.environ.get("GSC_REFRESH_TOKEN")
    if not (client_id and client_secret and refresh_token):
        return None
    return Credentials(
        token=None,
        refresh_token=refresh_token,
        client_id=client_id,
        client_secret=client_secret,
        token_uri=TOKEN_URI,
        scopes=SCOPES,
    )


def _from_token_file(path: Path) -> Credentials | None:
    if not path.exists():
        return None
    return Credentials.from_authorized_user_file(str(path), SCOPES)


def load_credentials(token_path: Path = DEFAULT_TOKEN_PATH) -> Credentials:
    """Return usable credentials, refreshing them if the access token is stale."""
    creds = _from_env() or _from_token_file(token_path)
    if creds is None:
        raise SystemExit(
            "No credentials found.\n"
            "Either set GSC_CLIENT_ID / GSC_CLIENT_SECRET / GSC_REFRESH_TOKEN,\n"
            "or run: python gsc_auth.py --client-secrets client_secret.json"
        )
    if not creds.valid:
        if not creds.refresh_token:
            raise SystemExit("Credentials expired and carry no refresh token; re-run gsc_auth.py.")
        creds.refresh(Request())
    return creds


def interactive_login(client_secrets: Path, token_path: Path = DEFAULT_TOKEN_PATH) -> Credentials:
    """One-time browser consent. Must run on a machine with a browser."""
    from google_auth_oauthlib.flow import InstalledAppFlow

    flow = InstalledAppFlow.from_client_secrets_file(str(client_secrets), SCOPES)
    # access_type=offline + prompt=consent is what actually returns a refresh token.
    creds = flow.run_local_server(port=0, access_type="offline", prompt="consent")
    token_path.write_text(creds.to_json())
    token_path.chmod(0o600)
    return creds


def main() -> None:
    parser = argparse.ArgumentParser(description="Authorize this tool against Search Console.")
    parser.add_argument(
        "--client-secrets",
        type=Path,
        required=True,
        help="OAuth client secrets JSON downloaded from Google Cloud (type: Desktop app).",
    )
    parser.add_argument("--token", type=Path, default=DEFAULT_TOKEN_PATH)
    args = parser.parse_args()

    creds = interactive_login(args.client_secrets, args.token)
    client = json.loads(args.client_secrets.read_text())
    installed = client.get("installed") or client.get("web") or {}

    print(f"\nToken written to {args.token}\n")
    print("To run headless (CI, remote agent), export these instead of shipping token.json:")
    print(f"  GSC_CLIENT_ID={installed.get('client_id', '<client_id>')}")
    print("  GSC_CLIENT_SECRET=<client_secret>")
    print(f"  GSC_REFRESH_TOKEN={creds.refresh_token}")


if __name__ == "__main__":
    main()
