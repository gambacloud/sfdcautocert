import threading
import time
import unittest
import urllib.request

from fastapi import FastAPI
from fastapi.testclient import TestClient

from sfdcautocert import api, discovery, limits, service
from sfdcautocert.model import CertRecord
from sfdcautocert.sf import metadata
from sfdcautocert.sf.auth import Session

H = {"X-Requested-With": "cert-manager"}


class CooldownAndBusyTests(unittest.TestCase):
    def setUp(self):
        self._scan = service.scan_org
        service.scan_org = lambda *a, **k: []

    def tearDown(self):
        service.scan_org = self._scan

    def _client(self):
        app = FastAPI()
        app.include_router(api.create_router(base="/cm", userinfo=lambda u, t: {"email": "a@b.c"}), prefix="/cm")
        c = TestClient(app, base_url="https://testserver")
        c.post("/cm/api/session", json={"access_token": "t", "instance_url": "https://x.my.salesforce.com"}, headers=H)
        time.sleep(0.3)  # the login scan finishes immediately (patched)
        return c

    def test_rescan_during_cooldown_is_429_with_retry_after(self):
        saved = limits.SCAN_COOLDOWN_S
        limits.SCAN_COOLDOWN_S = 30
        try:
            r = self._client().post("/cm/api/refresh", json={}, headers=H)
            self.assertEqual(r.status_code, 429)
            self.assertTrue(0 < int(r.headers["Retry-After"]) <= 30)
        finally:
            limits.SCAN_COOLDOWN_S = saved

    def test_busy_when_all_scan_slots_taken(self):
        inv = service.Inventory(lambda: Session("t", "https://x.my.salesforce.com"))
        taken = 0
        try:
            while service._SCAN_SLOTS.acquire(blocking=False):
                taken += 1
            inv.refresh()
            self.assertIn("busy", inv.error)
            self.assertFalse(inv.scanning)
        finally:
            for _ in range(taken):
                service._SCAN_SLOTS.release()
        inv.refresh()  # slots free again
        self.assertIsNone(inv.error)


class EndpointCapTests(unittest.TestCase):
    def test_only_max_hosts_are_probed_and_a_note_is_added(self):
        blobs = {f"remoteSiteSettings/S{i}.remoteSite":
                 f"<RemoteSiteSetting><url>https://host{i}.test-hosts.net</url></RemoteSiteSetting>".encode() for i in range(60)}
        probed = []
        orig = discovery.sources.scan_endpoint
        discovery.sources.scan_endpoint = lambda h, p, t=8.0, **k: probed.append(h) or CertRecord(source="endpoint", name=h)
        notes = []
        try:
            recs = discovery.scan_discovered(blobs, max_hosts=10, note=notes.append)
        finally:
            discovery.sources.scan_endpoint = orig
        self.assertEqual(len(probed), 10)
        self.assertEqual(len(recs), 10)
        self.assertIn("limited to 10 of 60", notes[0])


class ResponseSizeTests(unittest.TestCase):
    def test_oversized_soap_response_is_refused(self):
        class Resp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self, n=-1): return b"x" * (n if n > 0 else 10_000)

        saved, orig = limits.MAX_SOAP_RESPONSE, urllib.request.urlopen
        limits.MAX_SOAP_RESPONSE = 100
        urllib.request.urlopen = lambda *a, **k: Resp()
        try:
            with self.assertRaises(metadata.MetadataError) as cm:
                metadata.MetadataClient(Session("t", "https://x.my.salesforce.com"))._call("<noop/>")
            self.assertIn("larger than", str(cm.exception))
        finally:
            limits.MAX_SOAP_RESPONSE, urllib.request.urlopen = saved, orig


if __name__ == "__main__":
    unittest.main()
