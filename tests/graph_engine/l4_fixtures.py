"""Banco di prova L4 — sito locale deterministico con i casi difficili.

Un solo ``ThreadingHTTPServer`` (thread per richiesta: le pagine aperte
in parallelo dall'explorer non si bloccano a vicenda) serve otto
scenari, ognuno sotto il proprio prefisso:

==========  ==============================================================
``/mp/``    kit multi-pagina: i click cambiano URL (root → step2 → login)
``/spa/``   SPA a step: i click cambiano il DOM, mai l'URL
``/gate/``  gate Turnstile finto che si auto-risolve dopo 3,5s
``/jsr/``   redirect JS ritardato di 2s (evasione dei crawler veloci)
``/beacon/``polling continuo (fetch ogni 200ms): mai in networkidle
``/fr/``    click → fetch con risposta dopo 1s → render del form
``/meta/``  meta refresh verso una pagina finale
``/delay/`` pagina vuota che disegna il form di login dopo 4s
==========  ==============================================================

``run_scenario`` esegue l'explorer su uno scenario e restituisce una
**firma** del grafo indipendente dalla porta e dagli UUID: l'insieme
ordinato di ``(depth, path, dom_hash)`` degli stati e il conteggio dei
tipi di transizione.  ``tests/graph_engine/l4_golden.json`` contiene le
firme prodotte dall'explorer PRIMA della Fase B: ogni modifica a L4 deve
riprodurle identiche (``test_l4_equivalence.py``).

Rigenerare il golden (solo consapevolmente, a explorer invariato)::

    python -m tests.graph_engine.l4_fixtures --write-golden
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

GOLDEN_PATH = Path(__file__).with_name("l4_golden.json")

# Bottoni grandi e sopra la piega: lo scoring delle azioni li seleziona.
_BTN = 'class="btn"'
_STYLE = (
    "<style>.btn{display:inline-block;padding:10px 24px;background:#0078d4;"
    "color:#fff;text-decoration:none;font-size:16px;border:0;}</style>"
)


def _page(title: str, body: str, head: str = "") -> str:
    return (
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
        f"<title>{title}</title>{_STYLE}{head}</head><body>{body}</body></html>"
    )


_LOGIN_FORM = (
    "<h1>Sign in to your account</h1>"
    "<form action=\"/collect\" method=\"post\">"
    "<label for=\"email\">Email</label><input id=\"email\" name=\"email\" type=\"email\">"
    "<label for=\"pwd\">Password</label><input id=\"pwd\" name=\"pwd\" type=\"password\">"
    "</form>"
)

PAGES: dict[str, str] = {
    # 1 — kit multi-pagina
    "/mp/": _page(
        "Shared document",
        f"<h1>You have a new shared document</h1>"
        f"<a href=\"/mp/step2\" id=\"mp-continue\" {_BTN}>Continue</a>",
    ),
    "/mp/step2": _page(
        "Document preview",
        f"<h1>Document preview</h1><p>Sign in to view the full document.</p>"
        f"<a href=\"/mp/login\" id=\"mp-signin\" {_BTN}>Sign in</a>",
    ),
    "/mp/login": _page("Sign in", _LOGIN_FORM),
    # 2 — SPA a step (URL invariato)
    "/spa/": _page(
        "Secure portal",
        "<div id=\"app\"><h1>Secure message</h1>"
        f"<button id=\"spa-next\" {_BTN} onclick=\"step2()\">Next</button></div>"
        "<script>"
        "function step2(){document.getElementById('app').innerHTML="
        "'<h1>Identity check</h1><p>Confirm to continue.</p>"
        "<button id=\"spa-confirm\" class=\"btn\" onclick=\"step3()\">Confirm</button>';}"
        "function step3(){document.getElementById('app').innerHTML="
        "'<h1>Sign in</h1><input id=\"u\" type=\"email\"><input id=\"p\" type=\"password\">';}"
        "</script>",
    ),
    # 3 — gate Turnstile finto (auto-risoluzione dopo 3,5s)
    "/gate/": _page(
        "Sign in — Microsoft",
        "<h1>Sign in</h1><p id=\"status\">Verifying your browser security…</p>"
        "<iframe id=\"cf-challenge\" src=\"https://challenges.cloudflare.com/"
        "cdn-cgi/challenge-platform/h/g/turnstile/if/ov/av0/rcv0/0x4AAAA/0/"
        "light/normal\" width=\"300\" height=\"65\" style=\"border:0;\"></iframe>"
        f"<p><a href=\"/gate/next\" id=\"gate-next\" {_BTN}>Next</a></p>"
        "<script>setTimeout(()=>{const f=document.getElementById('cf-challenge');"
        "if(f)f.remove();document.getElementById('status').textContent='Verified';"
        "},3500);</script>",
    ),
    "/gate/next": _page("Verified", _LOGIN_FORM),
    # 4 — redirect JS ritardato
    "/jsr/": _page(
        "Loading",
        "<h1>Please wait…</h1>"
        "<script>setTimeout(()=>{window.location.href='/jsr/landing';},2000);</script>",
    ),
    "/jsr/landing": _page("Landing", _LOGIN_FORM),
    # 5 — polling continuo: la rete non va mai in idle
    "/beacon/": _page(
        "Account notice",
        "<h1>Unusual activity detected</h1>"
        f"<a href=\"/beacon/next\" id=\"beacon-continue\" {_BTN}>Continue</a>"
        "<script>setInterval(()=>{fetch('/beacon/ping').catch(()=>{});},200);</script>",
    ),
    "/beacon/next": _page(
        "Verify",
        _LOGIN_FORM
        + "<script>setInterval(()=>{fetch('/beacon/ping').catch(()=>{});},200);</script>",
    ),
    # 6 — click → fetch lenta → render
    "/fr/": _page(
        "Document access",
        "<div id=\"app\"><h1>Encrypted document</h1>"
        f"<button id=\"fr-verify\" {_BTN} onclick=\"go()\">Verify</button></div>"
        "<script>function go(){fetch('/fr/api').then(r=>r.text()).then(t=>{"
        "document.getElementById('app').innerHTML=t;});}</script>",
    ),
    # 7 — meta refresh
    "/meta/": _page(
        "Redirecting",
        "<p>Redirecting…</p>",
        head="<meta http-equiv=\"refresh\" content=\"0;url=/meta/target\">",
    ),
    "/meta/target": _page("Target", _LOGIN_FORM),
    # 8 — render ritardato: pagina vuota, il form compare dopo 4s
    "/delay/": _page(
        "Sign in to your Account",
        "<div id=\"root\"></div>"
        "<script>setTimeout(()=>{document.getElementById('root').innerHTML="
        "'<h1>Sign in</h1><input id=\"e\" type=\"email\"><input id=\"p\" type=\"password\">';},4000);</script>",
    ),
}

SCENARIOS: dict[str, str] = {
    "multipage": "/mp/",
    "spa": "/spa/",
    "gate": "/gate/",
    "js_redirect": "/jsr/",
    "beacon": "/beacon/",
    "fetch_render": "/fr/",
    "meta_refresh": "/meta/",
    "delayed_render": "/delay/",
}

FR_API_DELAY_S = 1.0


class _Handler(BaseHTTPRequestHandler):
    def _send(self, body: str, status: int = 200, ctype: str = "text/html") -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", f"{ctype}; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802 — API di BaseHTTPRequestHandler
        path = urlparse(self.path).path
        if path == "/beacon/ping":
            self._send("ok", ctype="text/plain")
        elif path == "/fr/api":
            time.sleep(FR_API_DELAY_S)
            self._send(_LOGIN_FORM, ctype="text/plain")
        elif path in PAGES:
            self._send(PAGES[path])
        else:
            self._send("not found", status=404, ctype="text/plain")

    def do_POST(self) -> None:  # noqa: N802
        self._send("ok", ctype="text/plain")

    def log_message(self, format, *args):  # noqa: A002 — firma della base class
        pass


class _QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address) -> None:
        # Le pagine chiuse dall'explorer interrompono richieste in volo
        # (es. i ping del polling): BrokenPipe atteso, non un errore.
        pass


class FixtureServer:
    """Server del banco di prova su una porta libera di 127.0.0.1."""

    def __enter__(self) -> "FixtureServer":
        self._server = _QuietServer(("127.0.0.1", 0), _Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self.base = f"http://127.0.0.1:{self._server.server_port}"
        return self

    def __exit__(self, *exc) -> None:
        self._server.shutdown()
        self._server.server_close()


def graph_signature(explorer) -> dict:
    """Firma del grafo indipendente da porta, UUID e ordine di scoperta."""
    states = sorted(
        {(s.depth, urlparse(s.url).path, s.dom_hash) for s in explorer.states}
    )
    kinds = Counter(
        t.kind.value if hasattr(t.kind, "value") else str(t.kind)
        for t in explorer.transitions
    )
    return {
        "states": [list(s) for s in states],
        "transition_kinds": dict(sorted(kinds.items())),
    }


async def run_scenario(browser, base: str, name: str) -> tuple[dict, float]:
    """Esegue l'explorer su uno scenario: (firma del grafo, secondi)."""
    from graph_engine.budget import Budget
    from graph_engine.explorer import StateGraphExplorer

    explorer = StateGraphExplorer(browser)
    started = time.monotonic()
    await explorer.run(
        base + SCENARIOS[name],
        budget=Budget(max_depth=4, max_nodes=20, timeout_s=120),
        capture_artifacts=False,
        top_n_actions=3,
        captcha_wait_s=5,
    )
    return graph_signature(explorer), time.monotonic() - started


async def _run_all() -> tuple[dict, dict]:
    from playwright.async_api import async_playwright

    signatures: dict = {}
    timings: dict = {}
    with FixtureServer() as srv:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                for name in SCENARIOS:
                    sig, elapsed = await run_scenario(browser, srv.base, name)
                    signatures[name] = sig
                    timings[name] = round(elapsed, 2)
            finally:
                await browser.close()
    return signatures, timings


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--write-golden", action="store_true",
                        help="sovrascrive l4_golden.json con le firme correnti")
    args = parser.parse_args()

    signatures, timings = asyncio.run(_run_all())
    print(json.dumps({"timings_s": timings, "total_s": round(sum(timings.values()), 2)}, indent=2))
    if args.write_golden:
        GOLDEN_PATH.write_text(json.dumps(signatures, indent=2, sort_keys=True) + "\n")
        print(f"golden scritto in {GOLDEN_PATH}")
    else:
        print(json.dumps(signatures, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
