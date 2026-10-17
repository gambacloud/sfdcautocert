"""Minimal Metadata API (SOAP) client: retrieve component types as {path: bytes}."""
from __future__ import annotations

import base64
import io
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from xml.sax.saxutils import escape

from .. import limits
from .auth import Session

NS = "{http://soap.sforce.com/2006/04/metadata}"


class MetadataError(RuntimeError):
    pass


class MetadataClient:
    def __init__(self, session: Session, api_version: str = "62.0"):
        self.s, self.v = session, api_version

    def _call(self, body: str) -> ET.Element:
        env = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<env:Envelope xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns="http://soap.sforce.com/2006/04/metadata">'
            f"<env:Header><SessionHeader><sessionId>{escape(self.s.access_token)}</sessionId></SessionHeader></env:Header>"
            f"<env:Body>{body}</env:Body></env:Envelope>"
        )
        req = urllib.request.Request(
            f"{self.s.instance_url}/services/Soap/m/{self.v}", data=env.encode(),
            headers={"Content-Type": "text/xml; charset=UTF-8", "SOAPAction": '""'})
        last = ""
        for attempt in range(3):  # transient 5xx / empty responses are retried
            try:
                with urllib.request.urlopen(req, timeout=120) as r:
                    raw = r.read(limits.MAX_SOAP_RESPONSE + 1)
                if len(raw) > limits.MAX_SOAP_RESPONSE:
                    raise MetadataError(f"response larger than {limits.MAX_SOAP_RESPONSE // (1024 * 1024)} MB; skipped")
                if raw.strip():
                    return ET.fromstring(raw)
                last = "empty response"
            except urllib.error.HTTPError as e:
                raw = e.read()
                try:
                    fault = ET.fromstring(raw).findtext(".//faultstring")
                except ET.ParseError:
                    fault = None
                if fault:
                    raise MetadataError(fault) from None
                last = f"HTTP {e.code} {e.reason}"
                if e.code < 500:
                    raise MetadataError(last) from None
            except (urllib.error.URLError, TimeoutError) as e:
                last = str(e)
            time.sleep(1.5 * (attempt + 1))
        raise MetadataError(f"Metadata API call failed: {last}")

    def deploy(self, files: dict[str, bytes], poll: float = 1.0, timeout: float = 180.0) -> None:
        """Deploy {path: content} (must include package.xml at the root). Raises MetadataError with the problems."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for name, data in files.items():
                z.writestr(name, data)
        body = (f"<deploy><ZipFile>{base64.b64encode(buf.getvalue()).decode()}</ZipFile>"
                "<DeployOptions><singlePackage>true</singlePackage><rollbackOnError>true</rollbackOnError></DeployOptions></deploy>")
        pid = self._call(body).find(f".//{NS}id").text
        deadline = time.time() + timeout
        while True:
            res = self._call(f"<checkDeployStatus><asyncProcessId>{pid}</asyncProcessId>"
                             "<includeDetails>true</includeDetails></checkDeployStatus>").find(f".//{NS}result")
            if res.findtext(f"{NS}done") == "true":
                break
            if time.time() > deadline:
                raise MetadataError("deploy timed out")
            time.sleep(poll)
        if res.findtext(f"{NS}success") != "true":
            problems = []
            for c in res.iter(f"{NS}componentFailures"):
                problems.append(f"{c.findtext(NS + 'fullName')}: {c.findtext(NS + 'problem')}")
            raise MetadataError("deploy failed: " + ("; ".join(problems) or res.findtext(f"{NS}errorMessage") or "unknown"))

    def retrieve(self, type_name: str, poll: float = 1.0, timeout: float = 180.0) -> dict[str, bytes]:
        """Retrieve all components of a type (wildcard). Returns {path: content}."""
        body = (
            "<retrieve><retrieveRequest>"
            f"<apiVersion>{self.v}</apiVersion><singlePackage>true</singlePackage>"
            f"<unpackaged><types><members>*</members><name>{escape(type_name)}</name></types><version>{self.v}</version></unpackaged>"
            "</retrieveRequest></retrieve>"
        )
        pid = self._call(body).find(f".//{NS}id").text
        deadline = time.time() + timeout
        while True:
            res = self._call(
                f"<checkRetrieveStatus><asyncProcessId>{pid}</asyncProcessId><includeZip>true</includeZip></checkRetrieveStatus>"
            ).find(f".//{NS}result")
            if res.findtext(f"{NS}done") == "true":
                break
            if time.time() > deadline:
                raise MetadataError(f"retrieve of {type_name} timed out")
            time.sleep(poll)
        if res.findtext(f"{NS}status") == "Failed":
            raise MetadataError(res.findtext(f"{NS}errorMessage") or f"retrieve of {type_name} failed")
        z = res.findtext(f"{NS}zipFile")
        if not z:
            return {}
        out = {}
        with zipfile.ZipFile(io.BytesIO(base64.b64decode(z))) as zf:
            if sum(i.file_size for i in zf.infolist()) > limits.MAX_UNZIPPED:
                raise MetadataError(f"{type_name}: more than {limits.MAX_UNZIPPED // (1024 * 1024)} MB of metadata; skipped")
            for n in zf.namelist():
                if n.endswith("/") or n == "package.xml":
                    continue
                out[n.removeprefix("unpackaged/")] = zf.read(n)
        return out
