import datetime as dt
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID as E, NameOID

from sfdcautocert import rotate
from sfdcautocert.issue import PurposeViolation

NOW = dt.datetime(2026, 10, 11, tzinfo=dt.timezone.utc)


class FakeSf:
    def __init__(self):
        self.key = rsa.generate_private_key(65537, 2048)
        self.deployed = []

    def deploy(self, files):
        self.deployed.append(files)

    def retrieve(self, t):
        name = next(k for k in self.deployed[0] if k.endswith(".crt"))
        csr = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "n")])).sign(self.key, hashes.SHA256()))
        return {name: csr.public_bytes(serialization.Encoding.PEM)}


class Signer:
    def __init__(self, ekus):
        self.ekus = ekus

    def sign(self, csr_pem):
        csr = x509.load_pem_x509_csr(csr_pem)
        k = rsa.generate_private_key(65537, 2048)
        n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA")])
        c = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(n).public_key(csr.public_key())
             .serial_number(7).not_valid_before(NOW).not_valid_after(NOW + dt.timedelta(days=47))
             .add_extension(x509.ExtendedKeyUsage(self.ekus), False).sign(k, hashes.SHA256()))
        return c.public_bytes(serialization.Encoding.PEM)


class RotateTests(unittest.TestCase):
    def test_rotate_names_and_deploys(self):
        sf = FakeSf()
        name = rotate.rotate(sf, "Partner_mTLS", Signer([E.CLIENT_AUTH]), now=NOW)
        self.assertEqual(name, "Partner_mTLS_20261011")
        self.assertEqual(len(sf.deployed), 2)  # CSR request + signed install
        self.assertIn(b"BEGIN CERTIFICATE", sf.deployed[1][f"certs/{name}.crt"])

    def test_dual_use_chain_is_not_installed(self):
        sf = FakeSf()
        with self.assertRaises(PurposeViolation):
            rotate.rotate(sf, "Partner_mTLS", Signer([E.SERVER_AUTH, E.CLIENT_AUTH]), now=NOW)
        self.assertEqual(len(sf.deployed), 1)  # only the CSR request, nothing installed


if __name__ == "__main__":
    unittest.main()
