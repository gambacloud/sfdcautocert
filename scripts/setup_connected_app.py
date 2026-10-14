"""One-off: create the SFDCAutoCert External Client App (JWT bearer, API scope) in an org and pre-authorise a user.

Salesforce no longer allows creating new Connected Apps in many orgs ("contact Support"), so this uses External Client Apps.

    python scripts/setup_connected_app.py <sf-alias> <username>

Writes the private key to .secrets/jwt_key.pem (git-ignored) and prints the consumer key. Idempotent.
"""
from __future__ import annotations

import datetime as dt
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

APP = "SFDCAutoCert"
PS = "SFDCAutoCert_Access"
SF = shutil.which("sf")
ROOT = Path(__file__).resolve().parent.parent
SECRETS = ROOT / ".secrets"
NS = 'xmlns="http://soap.sforce.com/2006/04/metadata"'
H = '<?xml version="1.0" encoding="UTF-8"?>\n'


def sf(*args: str, cwd=None) -> dict:
    p = subprocess.run([SF, *args, "--json"], capture_output=True, text=True, cwd=cwd)
    try:
        r = json.loads(p.stdout)
    except ValueError:
        raise SystemExit(f"sf {' '.join(args)} failed: {p.stderr or p.stdout}")
    if r.get("status") != 0:
        fails = [f.get("problem") for f in r.get("result", {}).get("details", {}).get("componentFailures", []) or []]
        raise SystemExit(f"sf {' '.join(args)} failed: {fails or r.get('message')}")
    return r


def ensure_key() -> str:
    SECRETS.mkdir(exist_ok=True)
    key_path, cert_path = SECRETS / "jwt_key.pem", SECRETS / "jwt_cert.pem"
    if not key_path.exists():
        key = rsa.generate_private_key(65537, 2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, APP)])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now)
                .not_valid_after(now + dt.timedelta(days=730)).sign(key, hashes.SHA256()))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path.read_text()


def soql(org: str, q: str) -> list[dict]:
    return sf("data", "query", "-q", q, "-o", org)["result"]["records"]


def main(org: str, username: str) -> None:
    cert_pem = ensure_key()
    tmp = Path(tempfile.mkdtemp(prefix="sfdcautocert-eca-"))
    try:
        b = tmp / "force-app/main/default"
        for d in ("externalClientApps", "extlClntAppOauthSettings", "extlClntAppGlobalOauthSets", "extlClntAppOauthPolicies"):
            (b / d).mkdir(parents=True)
        (tmp / "sfdx-project.json").write_text(json.dumps(
            {"packageDirectories": [{"path": "force-app", "default": True}], "sourceApiVersion": "62.0"}))
        (b / f"externalClientApps/{APP}.eca-meta.xml").write_text(H + f"""<ExternalClientApplication {NS}>
    <contactEmail>{username}</contactEmail>
    <distributionState>Local</distributionState>
    <isProtected>false</isProtected>
    <label>{APP}</label>
</ExternalClientApplication>
""")
        (b / f"extlClntAppOauthSettings/{APP}.ecaOauth-meta.xml").write_text(H + f"""<ExtlClntAppOauthSettings {NS}>
    <commaSeparatedOauthScopes>Api,RefreshToken</commaSeparatedOauthScopes>
    <externalClientApplication>{APP}</externalClientApplication>
    <label>{APP} OAuth</label>
</ExtlClntAppOauthSettings>
""")
        (b / f"extlClntAppGlobalOauthSets/{APP}.ecaGlblOauth-meta.xml").write_text(H + f"""<ExtlClntAppGlobalOauthSettings {NS}>
    <callbackUrl>http://localhost:1717/OauthRedirect</callbackUrl>
    <certificate>{cert_pem}</certificate>
    <externalClientApplication>{APP}</externalClientApplication>
    <isConsumerSecretOptional>false</isConsumerSecretOptional>
    <isNamedUserJwtEnabled>true</isNamedUserJwtEnabled>
    <label>{APP} Global OAuth</label>
</ExtlClntAppGlobalOauthSettings>
""")
        (b / f"extlClntAppOauthPolicies/{APP}_defaultPolicy.ecaOauthPlcy-meta.xml").write_text(H + f"""<ExtlClntAppOauthConfigurablePolicies {NS}>
    <externalClientApplication>{APP}</externalClientApplication>
    <ipRelaxationPolicyType>Enforce</ipRelaxationPolicyType>
    <isNamedUserJwtEnabled>true</isNamedUserJwtEnabled>
    <label>{APP}_defaultPolicy</label>
    <permittedUsersPolicyType>AdminApprovedPreAuthorized</permittedUsersPolicyType>
    <refreshTokenPolicyType>SpecificLifetime</refreshTokenPolicyType>
    <refreshTokenValidityPeriod>365</refreshTokenValidityPeriod>
    <refreshTokenValidityUnit>Days</refreshTokenValidityUnit>
    <requiredSessionLevel>STANDARD</requiredSessionLevel>
</ExtlClntAppOauthConfigurablePolicies>
""")
        sf("project", "deploy", "start", "-d", "force-app", "-o", org, cwd=tmp)
        sf("project", "retrieve", "start", "-m", f"ExtlClntAppGlobalOauthSettings:{APP}", "-o", org, cwd=tmp)
        xml = next(tmp.rglob(f"{APP}.ecaGlblOauth-meta.xml")).read_text()
        ck = re.search(r"<consumerKey>(.*?)</consumerKey>", xml).group(1)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # pre-authorise the user: permission set -> SetupEntityAccess on the external client app
    eca = soql(org, f"SELECT Id FROM ExternalClientApplication WHERE DeveloperName = '{APP}'")[0]["Id"]
    ps = soql(org, f"SELECT Id FROM PermissionSet WHERE Name = '{PS}'")
    ps_id = ps[0]["Id"] if ps else sf("data", "create", "record", "-s", "PermissionSet", "-v",
                                      f"Name={PS} Label={PS}", "-o", org)["result"]["id"]
    if not soql(org, f"SELECT Id FROM SetupEntityAccess WHERE ParentId='{ps_id}' AND SetupEntityId='{eca}'"):
        sf("data", "create", "record", "-s", "SetupEntityAccess", "-v", f"ParentId={ps_id} SetupEntityId={eca}", "-o", org)
    uid = soql(org, f"SELECT Id FROM User WHERE Username = '{username}'")[0]["Id"]
    if not soql(org, f"SELECT Id FROM PermissionSetAssignment WHERE PermissionSetId='{ps_id}' AND AssigneeId='{uid}'"):
        sf("data", "create", "record", "-s", "PermissionSetAssignment", "-v",
           f"PermissionSetId={ps_id} AssigneeId={uid}", "-o", org)

    print(f"External Client App '{APP}' ready. Consumer key: {ck}")
    print(f"Private key: {SECRETS / 'jwt_key.pem'}")
    print(f"Run: python -m sfdcautocert salesforce --jwt-client-id {ck} --jwt-username {username} --jwt-key .secrets/jwt_key.pem")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    main(sys.argv[1], sys.argv[2])
