import unittest
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID as E, NameOID

from sfdcautocert.analyze import build_record

NOW = datetime(2026, 10, 11, tzinfo=timezone.utc)


def make(days=30, ekus=None, self_signed=True, key_bits=2048, validity=47):
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example")])
    issuer = name if self_signed else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Some Public CA")])
    start = NOW + timedelta(days=days) - timedelta(days=validity)
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(start)
         .not_valid_after(NOW + timedelta(days=days)))
    if ekus:
        b = b.add_extension(x509.ExtendedKeyUsage(ekus), critical=False)
    return b.sign(key, hashes.SHA256())


def codes(rec):
    return {f.code: f.severity for f in rec.findings}


class AnalyzeTests(unittest.TestCase):
    def test_dual_use_public_is_critical(self):
        r = build_record(make(ekus=[E.SERVER_AUTH, E.CLIENT_AUTH], self_signed=False), "file", "x", now=NOW)
        self.assertEqual(codes(r)["DUAL_USE"], "CRITICAL")
        self.assertEqual(r.severity, "CRITICAL")

    def test_dual_use_self_signed_is_info(self):
        r = build_record(make(ekus=[E.SERVER_AUTH, E.CLIENT_AUTH]), "file", "x", now=NOW)
        self.assertEqual(codes(r)["DUAL_USE"], "INFO")

    def test_client_only_is_clean(self):
        r = build_record(make(ekus=[E.CLIENT_AUTH], self_signed=False), "file", "x", now=NOW)
        self.assertNotIn("DUAL_USE", codes(r))

    def test_expiry_bands(self):
        self.assertEqual(codes(build_record(make(days=5), "f", "x", now=NOW))["EXPIRES_SOON"], "HIGH")
        self.assertEqual(codes(build_record(make(days=15), "f", "x", now=NOW))["EXPIRES_SOON"], "MEDIUM")
        self.assertNotIn("EXPIRES_SOON", codes(build_record(make(days=40), "f", "x", now=NOW)))
        self.assertEqual(codes(build_record(make(days=-3), "f", "x", now=NOW))["EXPIRED"], "CRITICAL")

    def test_weak_key_and_lifetime(self):
        r = build_record(make(key_bits=1024, self_signed=False, validity=365), "f", "x", now=NOW)
        self.assertEqual(codes(r)["WEAK_KEY"], "HIGH")
        self.assertIn("LONG_LIFETIME", codes(r))


class UsageTests(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives import serialization
        from sfdcautocert.sources import records_from_blobs
        self.pem = make(days=30, self_signed=False).public_bytes(serialization.Encoding.PEM)
        self.records_from_blobs = records_from_blobs

    def test_usages_exact_text_pem(self):
        from sfdcautocert.usage import map_usages
        blobs = {"certs/MyCert.crt": self.pem}
        recs = self.records_from_blobs(blobs, "salesforce")
        pems = {"certs/MyCert.crt": self.pem.decode()}
        comps = {
            "samlssoconfigs/Sso.samlssoconfig": b"<SamlSsoConfig><validationCert>MyCert</validationCert></SamlSsoConfig>",
            "classes/Callout.cls": b"req.setClientCertificateName('MyCert');",
            "connectedApps/App.connectedApp": b"<ConnectedApp><oauthConfig><certificate>" + self.pem + b"</certificate></oauthConfig></ConnectedApp>",
            "classes/Other.cls": b"String s = 'MyCertificateFoo';",
        }
        map_usages(recs, comps, pems)
        got = {(u.kind, u.component, u.confidence) for u in recs[0].usages}
        self.assertEqual(got, {("SamlSsoConfig", "Sso", "exact"), ("ApexClass", "Callout", "text"),
                               ("ConnectedApp", "App", "pem")})
        self.assertEqual(max(u.weight for u in recs[0].usages), 100)
        self.assertNotIn("UNUSED", codes(recs[0]))

    def test_unused_flagged(self):
        from sfdcautocert.usage import map_usages
        recs = self.records_from_blobs({"certs/Lonely.crt": self.pem}, "salesforce")
        map_usages(recs, {}, {})
        self.assertIn("UNUSED", codes(recs[0]))


if __name__ == "__main__":
    unittest.main()
