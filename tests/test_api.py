import unittest

from fastapi import FastAPI
from fastapi.testclient import TestClient

from sfdcautocert import api, service
from sfdcautocert import sources

H = {"X-Requested-With": "cert-manager"}


def make_client(userinfo=None):
    app = FastAPI()
    app.include_router(api.create_router(base="/cert-manager", client_id="CID",
                                         userinfo=userinfo or (lambda url, tok: {"preferred_username": "a@b.c", "organization_id": "00D"})),
                       prefix="/cert-manager")
    return TestClient(app, base_url="https://testserver")


class ApiTests(unittest.TestCase):
    def setUp(self):
        self._scan = service.scan_org
        service.scan_org = lambda *a, **k: []  # no Salesforce in unit tests

    def tearDown(self):
        service.scan_org = self._scan

    def test_page_and_config(self):
        c = make_client()
        r = c.get("/cert-manager")
        self.assertEqual(r.status_code, 200)
        self.assertIn('const BASE = "/cert-manager"', r.text)
        self.assertEqual(c.get("/cert-manager/api/config").json()["clientId"], "CID")

    def test_inventory_requires_login(self):
        c = make_client()
        self.assertEqual(c.get("/cert-manager/api/inventory").status_code, 401)
        self.assertFalse(c.get("/cert-manager/api/me").json()["authenticated"])

    def test_rejects_non_salesforce_instance_and_missing_header(self):
        c = make_client()
        body = {"access_token": "t", "instance_url": "https://evil.example.com"}
        self.assertEqual(c.post("/cert-manager/api/session", json=body, headers=H).status_code, 400)
        ok = {"access_token": "t", "instance_url": "https://x.my.salesforce.com"}
        self.assertEqual(c.post("/cert-manager/api/session", json=ok).status_code, 403)  # no X-Requested-With

    def test_login_inventory_logout(self):
        c = make_client()
        r = c.post("/cert-manager/api/session", json={"access_token": "t", "instance_url": "https://x.my.salesforce.com"}, headers=H)
        self.assertEqual(r.status_code, 200)
        self.assertIn("HttpOnly", r.headers["set-cookie"])
        self.assertTrue(c.get("/cert-manager/api/me").json()["authenticated"])
        inv = c.get("/cert-manager/api/inventory")
        self.assertEqual(inv.status_code, 200)
        self.assertIn("summary", inv.json())
        self.assertNotIn("access_token", inv.text)
        c.post("/cert-manager/api/logout", headers=H)
        self.assertEqual(c.get("/cert-manager/api/inventory").status_code, 401)

    def test_bad_token_rejected(self):
        def boom(url, tok):
            raise RuntimeError("401")
        c = make_client(boom)
        r = c.post("/cert-manager/api/session", json={"access_token": "t", "instance_url": "https://x.my.salesforce.com"}, headers=H)
        self.assertEqual(r.status_code, 401)

    def test_instance_url_normalisation(self):
        self.assertEqual(api.normalize_instance_url("https://Foo.my.salesforce.com/path"), "https://foo.my.salesforce.com")
        for bad in ("http://a.my.salesforce.com", "https://a.salesforce.com.evil.com", "https://u:p@a.salesforce.com",
                    "https://a.salesforce.com:8443"):
            with self.assertRaises(ValueError):
                api.normalize_instance_url(bad)


class SsrfTests(unittest.TestCase):
    def test_connect_falls_back_to_next_address(self):
        import socket
        import threading
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        threading.Thread(target=lambda: srv.accept(), daemon=True).start()
        # first address is dead (TEST-NET-1 would hang; use an unbound loopback port instead)
        dead = socket.socket()
        dead.bind(("127.0.0.2", 0))
        dead_port = dead.getsockname()[1]
        dead.close()
        s = sources._connect(["127.0.0.1"], port, 2.0)
        s.close()
        with self.assertRaises(OSError):
            sources._connect(["127.0.0.2"], dead_port, 1.0)
        srv.close()

    def test_private_addresses_not_scanned(self):
        r = sources.scan_endpoint("127.0.0.1", 443)
        self.assertTrue(any(f.code == "NOT_SCANNED" for f in r.findings))


if __name__ == "__main__":
    unittest.main()
