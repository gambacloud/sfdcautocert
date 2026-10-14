"""Live check of the CSR flow through the backend (JWT session): request CSR -> sign with a local test CA -> install.

    python scripts/csr_e2e.py <consumer-key> <username> [DevName]
"""
import datetime as dt
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID as E, NameOID

from sfdcautocert import certstore
from sfdcautocert.sf import auth
from sfdcautocert.sf.metadata import MetadataClient

key_id, user = sys.argv[1], sys.argv[2]
name = sys.argv[3] if len(sys.argv) > 3 else "AutoCertE2E"
root = Path(__file__).resolve().parent.parent
client = MetadataClient(auth.from_jwt_bearer(key_id, user, root / ".secrets/jwt_key.pem"))

csr = certstore.request_csr(client, name)
print("CSR subject:", csr.subject.rfc4514_string())
try:
    print("CSR SAN:", csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)
except x509.ExtensionNotFound:
    print("CSR SAN: none")
print("CSR key:", type(csr.public_key()).__name__, csr.public_key().key_size)

ca_key = ec.generate_private_key(ec.SECP256R1())
ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
now = dt.datetime.now(dt.timezone.utc)
leaf = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(ca_name).public_key(csr.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + dt.timedelta(days=47))
        .add_extension(x509.ExtendedKeyUsage([E.CLIENT_AUTH]), False).sign(ca_key, hashes.SHA256()))
certstore.install_signed(client, name, leaf.public_bytes(serialization.Encoding.PEM))
got = x509.load_pem_x509_certificates(client.retrieve("Certificate")[f"certs/{name}.crt"])
print("installed:", got[0].fingerprint(hashes.SHA256()) == leaf.fingerprint(hashes.SHA256()),
      "| days left", (got[0].not_valid_after_utc - now).days)
