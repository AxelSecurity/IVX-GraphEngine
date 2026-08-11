"""Euristica DGA (Domain Generation Algorithm) basata su entropia.

Punteggio 0-1 dove valori alti indicano un dominio probabilmente
generato algoritmicamente (tipico di malware / botnet).
"""

from __future__ import annotations

import math
import re

# ---------------------------------------------------------------------------
# Shannon entropy
# ---------------------------------------------------------------------------


def shannon_entropy(s: str) -> float:
    """Entropia di Shannon (bit per carattere) della stringa *s*."""
    if not s:
        return 0.0
    n = len(s)
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    for cnt in counts.values():
        p = cnt / n
        entropy -= p * math.log2(p)
    return entropy


# ---------------------------------------------------------------------------
# DGA score
# ---------------------------------------------------------------------------

# Pesi configurabili — documentati come costanti nominate
_W_CONSONANT_VOWEL = 0.35   # rapporto consonanti/vocali sbilanciato
_W_ENTROPY = 0.35           # entropia di Shannon alta
_W_DIGIT_RATIO = 0.30       # troppe cifre rispetto alla lunghezza

# Soglie
_CV_MIN_NORMAL = 0.5        # sotto questo rapporto C/V è anomalo
_CV_MAX_NORMAL = 4.0        # sopra questo rapporto C/V è anomalo
_ENTROPY_THRESHOLD = 3.0    # bit/carattere: sopra è sospetto
_DIGIT_RATIO_THRESHOLD = 0.30  # >30% cifre è sospetto

_VOWELS = frozenset("aeiou")
_CONSONANTS = frozenset("bcdfghjklmnpqrstvwxyz")


def _label_entropy_and_ratios(domain: str) -> tuple[float, float, float, int]:
    """Calcola entropia media, rapporto C/V, rapporto cifre e label count."""
    # Considera solo il dominio senza TLD per l'analisi
    # L'hostname è già il dominio registrabile o label estratti
    labels = [lbl for lbl in domain.lower().split(".") if lbl]
    # Salta il TLD (ultima label) — non contribuisce all'entropia DGA
    if len(labels) > 1:
        labels = labels[:-1]

    total_entropy = 0.0
    total_cv_score = 0.0
    total_digit_ratio = 0.0
    count = 0

    for label in labels:
        if len(label) < 3:
            continue
        count += 1
        # Entropia del label
        total_entropy += shannon_entropy(label)

        # Rapporto consonanti/vocali
        vowels = sum(1 for ch in label if ch in _VOWELS)
        consonants = sum(1 for ch in label if ch in _CONSONANTS)
        if vowels > 0:
            cv_ratio = consonants / vowels
            # Penalità se fuori dall'intervallo normale
            if cv_ratio < _CV_MIN_NORMAL or cv_ratio > _CV_MAX_NORMAL:
                total_cv_score += 1.0
        elif consonants > 0:
            total_cv_score += 1.0  # zero vocali → massima anomalia

        # Rapporto cifre
        digits = sum(1 for ch in label if ch.isdigit())
        digit_ratio = digits / len(label)
        if digit_ratio > _DIGIT_RATIO_THRESHOLD:
            total_digit_ratio += digit_ratio

    if count == 0:
        return 0.0, 0.0, 0.0, 0

    avg_entropy = total_entropy / count

    # Normalizza entropia: sopra soglia → contributo proporzionale
    if avg_entropy > _ENTROPY_THRESHOLD:
        entropy_signal = min(1.0, (avg_entropy - _ENTROPY_THRESHOLD) / 2.0)
    else:
        entropy_signal = 0.0

    cv_signal = min(1.0, total_cv_score / count)
    digit_signal = min(1.0, total_digit_ratio / count)

    weighted = (
        _W_ENTROPY * entropy_signal
        + _W_CONSONANT_VOWEL * cv_signal
        + _W_DIGIT_RATIO * digit_signal
    )

    return weighted, avg_entropy, cv_signal, count


def dga_score(hostname: str) -> float:
    """Punteggio DGA 0-1 per *hostname*.

    Combina entropia, rapporto consonanti/vocali, e densità di cifre
    con pesi documentati.  Valori > 0.6 sono forti indicatori di
    dominio generato algoritmicamente.
    """
    score, _, _, _ = _label_entropy_and_ratios(hostname)
    return round(min(1.0, score), 4)
