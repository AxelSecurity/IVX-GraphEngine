#!/bin/sh
# Entrypoint del container — gira come root SOLO per preparare la
# directory dati, poi cede i privilegi all'utente non-root (UID 10001)
# prima di eseguire il comando (uvicorn).
#
# Perché: al primo avvio il bind mount ./data può non esistere e viene
# creato dal demone Docker come root — l'app (non-root) non potrebbe
# aprirvi il DB SQLite ("unable to open database file").  Il chown qui
# rende il primo deploy automatico, senza interventi sull'host.
# Solo sulla directory: i file già presenti (DB, artefatti) appartengono
# all'app e non vanno toccati.
set -eu

mkdir -p /app/data
chown 10001:10001 /app/data

exec setpriv --reuid=10001 --regid=10001 --clear-groups "$@"
