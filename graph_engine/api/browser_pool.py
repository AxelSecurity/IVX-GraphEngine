"""Pool del browser Chromium condiviso tra le richieste API.

Prima di questo modulo ogni analisi lanciava un processo Chromium
dedicato (~5-6s di overhead misurati con la diagnostica [TIMING] del
2026-08-28) e lo chiudeva a fine pipeline.  Il pool mantiene UNA
istanza per l'intera vita dell'applicazione (avviata nel lifespan di
FastAPI e chiusa allo shutdown):

- **isolamento totale tra analisi**: ``StateGraphExplorer.run()`` crea
  un ``new_context()`` fresco per ogni esplorazione (cookie, storage e
  cache non si mescolano mai — solo il processo Chromium è condiviso);
- **autoriparazione**: se il browser condiviso muore (crash, OOM),
  ``acquire()`` tenta UN rilancio automatico per acquisizione; se anche
  il rilancio fallisce restituisce ``None`` e il chiamante degrada a un
  browser effimero per quella singola analisi — il servizio non resta
  mai rotto in attesa di un riavvio manuale del container.

Il CLI non usa il pool: un processo single-shot continua a lanciare il
proprio browser effimero come sempre.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from playwright.async_api import Browser, async_playwright

logger = logging.getLogger(__name__)


class BrowserPool:
    """Un Chromium condiviso con riavvio automatico su crash.

    Thread-safe rispetto al loop asyncio: le acquisizioni concorrenti
    sono serializzate da un ``asyncio.Lock`` — due richieste che
    arrivano insieme su un browser morto vedono UN solo rilancio.
    """

    def __init__(self) -> None:
        self._browser: Optional[Browser] = None
        self._pw = None  # istanza playwright avviata con .start()
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        """Avvia il processo Chromium condiviso.

        Un fallimento in avvio NON solleva: il pool resta vuoto e
        ``acquire()`` tenterà il rilancio alla prima richiesta (il
        chiamante degrada a browser effimero se anche quello fallisce).
        """
        try:
            self._pw = await async_playwright().start()
            self._browser = await self._pw.chromium.launch(headless=True)
            logger.info("BrowserPool: Chromium condiviso avviato")
        except Exception:
            logger.exception(
                "BrowserPool: avvio fallito — si useranno browser effimeri",
            )
            self._browser = None

    async def stop(self) -> None:
        """Chiude il browser condiviso e il driver playwright."""
        if self._browser is not None:
            try:
                await self._browser.close()
            except Exception:
                logger.exception("BrowserPool: errore in chiusura browser")
        if self._pw is not None:
            try:
                await self._pw.stop()
            except Exception:
                logger.exception("BrowserPool: errore in stop del driver")

    async def acquire(self) -> Optional[Browser]:
        """Ritorna il browser condiviso, rilanciandolo UNA volta se morto.

        Returns:
            Il ``Browser`` riusabile, oppure ``None`` se il browser è
            morto e il rilancio automatico non è riuscito — il chiamante
            deve degradare a un browser effimero per quell'analisi.
        """
        async with self._lock:
            if self._browser is not None and self._browser.is_connected():
                return self._browser

            # Browser morto o mai avviato: un solo tentativo di rilancio.
            # Se fallisce, si risponde None (degradazione effimera per
            # questa richiesta); la prossima acquisizione riproverà.
            try:
                if self._pw is None:
                    self._pw = await async_playwright().start()
                self._browser = await self._pw.chromium.launch(headless=True)
                logger.info("BrowserPool: Chromium rilanciato dopo crash")
                return self._browser
            except Exception:
                logger.exception(
                    "BrowserPool: rilancio fallito — degrado a browser "
                    "effimero per questa analisi",
                )
                self._browser = None
                return None
