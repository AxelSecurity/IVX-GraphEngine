# IVX-GraphEngine

Motore di esplorazione a grafo di stati per l'analisi dinamica di URL di phishing — segue
redirect multipli e interazioni utente (click, form) fino al payload finale. Componente
indipendente della toolchain Horus/IntelIVX, pensato per essere integrato via API.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
playwright install chromium
```
