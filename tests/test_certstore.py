import datetime as dt
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from sfdcautocert import certstore
from sfdcautocert.sf.metadata import MetadataError


class FakeClient:
    def __init__(self):
        self.key = rsa.generate_private_key(65537, 2048)
        self.files = {}

    def deploy(self, files):
        self.files = files

    def retrieve(self, type_name):
        if self.files.get("certs/X.crt") == b"":  # pending -> Salesforce returns a CSR
            csr = (x509.CertificateSigningRequestBuilder()
                   .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "X")])).sign(self.key, hashes.SHA256()))
            return {"certs/X.crt": csr.public_bytes(serialization.Encoding.PEM)}
        return {"certs/X.crt": b"-----BEGIN CERTIFICATE-----"}


def sign(pub, key):
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA")])
    now = dt.datetime.now(dt.timezone.utc)
    return (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "X")]))
            .issuer_name(n).public_key(pub).serial_number(5).not_valid_before(now)
            .not_valid_after(now + dt.timedelta(days=47)).sign(key, hashes.SHA256()))


class CertStoreTests(unittest.TestCase):
    def test_roundtrip_and_package(self):
        c = FakeClient()
        csr = certstore.request_csr(c, "X")
        self.assertIn("package.xml", c.files)
        self.assertIn(b"<caSigned>true</caSigned>", c.files["certs/X.crt-meta.xml"])
        leaf = sign(csr.public_key(), rsa.generate_private_key(65537, 2048))
        certstore.install_signed(c, "X", leaf.public_bytes(serialization.Encoding.PEM))
        self.assertIn(b"BEGIN CERTIFICATE", c.files["certs/X.crt"])

    def test_rejects_wrong_key(self):
        c = FakeClient()
        certstore.request_csr(c, "X")
        other = rsa.generate_private_key(65537, 2048)
        with self.assertRaises(MetadataError):
            certstore.install_signed(c, "X", sign(other.public_key(), other).public_bytes(serialization.Encoding.PEM))


if __name__ == "__main__":
    unittest.main()
