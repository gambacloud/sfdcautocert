from __future__ import annotations

import argparse
import json
import os
import sys
import warnings
from pathlib import Path

from . import relevance, report, service, sources
from .sf import auth


def _session_factory(args):
    if args.jwt_client_id:
        return lambda: auth.from_jwt_bearer(args.jwt_client_id, args.jwt_username, Path(args.jwt_key), args.login_url)
    return lambda: auth.from_sf_cli(args.org)


def _salesforce(args) -> list:
    return service.scan_org(_session_factory(args)(), args.api_version, not args.no_usage,
                            not (args.no_usage or args.no_endpoints))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="sfdcautocert",
                                description="Salesforce certificate discovery, usage mapping & risk audit")
    p.add_argument("--out", type=Path, help="directory for report.json / report.csv / report.html")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("salesforce", help="scan certificates + usages in an org (server-side Metadata API calls)")
    s.add_argument("org", nargs="?", help="sf CLI org alias/username (dev auth); omit when using --jwt-*")
    s.add_argument("--api-version", default="62.0")
    s.add_argument("--no-usage", action="store_true", help="skip usage mapping (and endpoint discovery)")
    s.add_argument("--no-endpoints", action="store_true", help="skip discovery/TLS scan of endpoints referenced by the org")
    s.add_argument("--jwt-client-id", default=os.getenv("SF_CLIENT_ID"), help="Connected App consumer key (JWT bearer)")
    s.add_argument("--jwt-username", default=os.getenv("SF_USERNAME"))
    s.add_argument("--jwt-key", default=os.getenv("SF_JWT_KEY_FILE"), help="PEM private key file")
    s.add_argument("--login-url", default=os.getenv("SF_LOGIN_URL", "https://login.salesforce.com"))
    s.add_argument("--config", type=Path, help="JSON file: client_id, username, key_file[, login_url]")

    v = sub.add_parser("serve", help="run the dashboard + JSON API (all Salesforce calls happen server-side)")
    v.add_argument("org", nargs="?", help="sf CLI org alias (dev auth); omit when using --jwt-*")
    v.add_argument("--api-version", default="62.0")
    v.add_argument("--host", default="127.0.0.1")
    v.add_argument("--port", type=int, default=8765)
    v.add_argument("--no-endpoints", action="store_true")
    v.add_argument("--config", type=Path, help="JSON file: client_id, username, key_file[, login_url]")
    v.add_argument("--jwt-client-id", default=os.getenv("SF_CLIENT_ID"))
    v.add_argument("--jwt-username", default=os.getenv("SF_USERNAME"))
    v.add_argument("--jwt-key", default=os.getenv("SF_JWT_KEY_FILE"))
    v.add_argument("--login-url", default=os.getenv("SF_LOGIN_URL", "https://login.salesforce.com"))

    f = sub.add_parser("files", help="scan .crt/.pem/.cer files or a retrieved metadata folder")
    f.add_argument("paths", nargs="+", type=Path)

    e = sub.add_parser("endpoints", help="TLS handshake against host[:port] targets")
    e.add_argument("hosts", nargs="*")
    e.add_argument("--file", type=Path, help="text file with one host[:port] per line")
    e.add_argument("--sf-defaults", action="store_true", help="include login/test/api.salesforce.com")

    args = p.parse_args(argv)
    if getattr(args, "config", None):  # keeps credentials out of command lines / launch files
        cfg = json.loads(Path(args.config).read_text())
        args.jwt_client_id = args.jwt_client_id or cfg.get("client_id")
        args.jwt_username = args.jwt_username or cfg.get("username")
        if not args.jwt_key and cfg.get("key_file"):  # relative paths resolve against the config file
            args.jwt_key = str((Path(args.config).parent / cfg["key_file"]).resolve())
        if cfg.get("login_url") and args.login_url == "https://login.salesforce.com":
            args.login_url = cfg["login_url"]
    warnings.filterwarnings("ignore", message="Attribute.s length")  # malformed country codes in some CA certs

    if args.cmd == "serve":
        if not (args.org or args.jwt_client_id):
            p.error("give an sf org alias, or --jwt-client-id/--jwt-username/--jwt-key")
        import uvicorn
        from fastapi import FastAPI

        from .api import create_router
        inv = service.Inventory(_session_factory(args), org_label=args.jwt_username or args.org,
                                api_version=args.api_version, with_endpoints=not args.no_endpoints)
        inv.refresh_async()
        app = FastAPI(title="SFDCAutoCert")
        app.include_router(create_router(base="/cert-manager", dev_inventory=inv, api_version=args.api_version),
                           prefix="/cert-manager")  # same path as in production

        @app.get("/", include_in_schema=False)
        def _root():
            from fastapi.responses import RedirectResponse
            return RedirectResponse("/cert-manager")

        print(f"Dashboard: http://{args.host}:{args.port}/cert-manager  (Ctrl+C to stop)")
        uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
        return 0
    if args.cmd == "salesforce":
        if not (args.org or args.jwt_client_id):
            p.error("give an sf org alias, or --jwt-client-id/--jwt-username/--jwt-key")
        records = _salesforce(args)
    elif args.cmd == "files":
        records = [r for path in args.paths for r in sources.scan_files(path)]
    else:
        targets = list(args.hosts)
        if args.file:
            targets += [l.strip() for l in args.file.read_text().splitlines() if l.strip() and not l.startswith("#")]
        if args.sf_defaults:
            targets += sources.SF_DEFAULT_ENDPOINTS
        if not targets:
            p.error("no targets given")
        records = sources.scan_endpoints(targets)
        for r in records:
            r.relevance, r.relevance_reason = relevance.classify(r)

    print(report.console(records))
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        report.write_json(records, args.out / "report.json")
        report.write_csv(records, args.out / "report.csv")
        report.write_html(records, args.out / "report.html")
        print(f"\nReports written to {args.out}")
    return 2 if any(r.severity == "CRITICAL" for r in records) else 0


if __name__ == "__main__":
    sys.exit(main())
