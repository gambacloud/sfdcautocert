import unittest

from fastapi import FastAPI
from fastapi.testclient import TestClient

from sfdcautocert import api, apex, relevance, service, usage
from sfdcautocert.model import CertRecord
from sfdcautocert.sf import tooling

H = {"X-Requested-With": "cert-manager"}


class ApexFilterTests(unittest.TestCase):
    def test_relevance_markers_and_cert_names(self):
        self.assertTrue(apex.is_relevant("req.setClientCertificateName('X');", []))
        self.assertTrue(apex.is_relevant("req.setEndpoint('callout:Foo/bar');", []))
        self.assertTrue(apex.is_relevant("String c = 'MyPartnerCert';", ["MyPartnerCert"]))
        self.assertFalse(apex.is_relevant("public class Plain { Integer add(Integer a){return a+1;} }", ["MyPartnerCert"]))

    def test_scan_skips_managed_batches_and_keeps_only_relevant(self):
        calls = []
        rows = {
            "ApexClass": [{"Id": f"01p{i:03d}", "Name": f"C{i}", "NamespacePrefix": "pkg" if i % 2 else None,
                           "Body": "req.setEndpoint('https://x.example.com');" if i == 4 else "class A {}"}
                          for i in range(60)],
            "ApexTrigger": [],
        }

        def fake_query(session, soql, api_version="62.0"):
            calls.append(soql)
            kind = "ApexClass" if "FROM ApexClass" in soql else "ApexTrigger"
            if "WHERE Id IN" in soql:
                ids = {s.strip("'") for s in soql.split("IN (")[1].rstrip(")").split(",")}
                return [r for r in rows[kind] if r["Id"] in ids]
            return rows[kind]

        orig = tooling.query
        tooling.query = fake_query
        try:
            blobs, stats = apex.scan_apex(object(), [])
        finally:
            tooling.query = orig
        self.assertEqual(list(blobs), ["classes/C4.cls"])
        self.assertEqual(stats["managed_skipped"], 30)
        self.assertEqual(stats["scanned"], 30)
        body_queries = [c for c in calls if "Body" in c]
        self.assertEqual(len(body_queries), 2)  # 30 unmanaged ids -> batches of 25 + 5


class ScopeTests(unittest.TestCase):
    def test_metadata_types_per_scope(self):
        std = usage.metadata_types("standard")
        self.assertNotIn("ApexClass", std)
        self.assertIn("Settings", std)  # holds the Identity Provider certificate
        self.assertNotIn("CustomSite", std)
        self.assertIn("CustomSite", usage.metadata_types("all"))
        self.assertNotIn("ApexClass", usage.metadata_types("all"))  # Apex goes through apex.scan_apex
        with self.assertRaises(ValueError):
            usage.metadata_types("everything")

    def test_unreferenced_cert_not_called_cleanup_without_apex_scan(self):
        rec = CertRecord(source="salesforce", name="Old", days_left=-5, extra={"apex_scanned": False})
        self.assertEqual(relevance.classify(rec)[0], "WATCH")
        rec.extra["apex_scanned"] = True
        self.assertEqual(relevance.classify(rec)[0], "CLEANUP")

    def test_refresh_validates_and_applies_scope(self):
        seen = []
        orig = service.scan_org
        service.scan_org = lambda *a, **k: seen.append(k.get("scope")) or []
        try:
            app = FastAPI()
            app.include_router(api.create_router(base="/cm", userinfo=lambda u, t: {"email": "a@b.c"}), prefix="/cm")
            c = TestClient(app, base_url="https://testserver")
            c.post("/cm/api/session", json={"access_token": "t", "instance_url": "https://x.my.salesforce.com"}, headers=H)
            self.assertEqual(c.post("/cm/api/refresh", json={"scope": "bogus"}, headers=H).status_code, 400)
            import time
            time.sleep(0.5)  # let the login scan finish
            self.assertEqual(c.post("/cm/api/refresh", json={"scope": "apex"}, headers=H).status_code, 202)
            time.sleep(0.5)
            self.assertEqual(c.get("/cm/api/inventory").json()["scope"], "apex")
            self.assertEqual(seen[0], "standard")  # default scan after login never reads Apex
            self.assertIn("apex", seen)
        finally:
            service.scan_org = orig


if __name__ == "__main__":
    unittest.main()
