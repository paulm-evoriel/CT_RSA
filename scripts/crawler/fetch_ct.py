#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fetch_ct.py — version robuste
- vérifie tree_size via get-sth
- télécharge par batches (get-entries?start=S&end=E)
- retries + backoff
- checkpoint & sharding
"""

import asyncio
import aiohttp
import json
import gzip
import logging
import math
import time
from pathlib import Path

# === Configuration ===
CT_LOG_URL = "https://ct.googleapis.com/logs/argon2024"  # base URL du log
SHARD_SIZE = 500       # nombre d'entrées par shard (pour fichiers de sortie)
BATCH_SIZE = 100            # nombre d'entries demandées par requête get-entries
CONCURRENCY = 6             # nombre max de requêtes HTTP concurrentes
MAX_RETRIES = 5
STATE_FILE = Path("data/state.json")
OUTPUT_DIR = Path("data/raw")
LOG_FILE = Path("data/logs/fetch.log")
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=30)

# Logging
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# === Helpers état ===
def load_state():
    if STATE_FILE.exists():
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"next_index": 0}

def save_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f)

# === Interroger get-sth pour connaître la taille actuelle du log ===
async def get_tree_size(session):
    url = f"{CT_LOG_URL}/ct/v1/get-sth"
    try:
        async with session.get(url) as resp:
            if resp.status == 200:
                j = await resp.json()
                ts = j.get("tree_size")
                logging.info(f"tree_size obtenu : {ts}")
                return int(ts)
            else:
                logging.error(f"get-sth returned HTTP {resp.status}")
                return None
    except Exception as e:
        logging.error(f"Exception get-sth: {e}")
        return None

# === Requête get-entries pour une plage start..end with retries/backoff ===
async def fetch_entries_range(session, start, end):
    url = f"{CT_LOG_URL}/ct/v1/get-entries?start={start}&end={end}"
    backoff = 1.0
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            async with session.get(url) as resp:
                if resp.status == 200:
                    j = await resp.json()
                    entries = j.get("entries", [])
                    return entries
                elif resp.status == 404:
                    # 404 : endpoint ok mais pas trouvé ; peut signifier que la plage est hors tree_size
                    logging.warning(f"404 pour plage {start}-{end}")
                    return None
                else:
                    logging.warning(f"HTTP {resp.status} pour {start}-{end} (attempt {attempt})")
        except Exception as e:
            logging.warning(f"Exception fetch {start}-{end} (attempt {attempt}): {e}")
        # backoff
        await asyncio.sleep(backoff)
        backoff *= 2
    logging.error(f"Échec après {MAX_RETRIES} tentatives pour {start}-{end}")
    return None

# === Téléchargement d'un bloc (shard) complet en batches concurrents ===
async def fetch_shard(session, shard_start, shard_end, semaphore):
    """
    Télécharge les entrées [shard_start, shard_end) en faisant des requêtes par BATCH_SIZE
    retourne la liste d'objets entry (mêmes structures que get-entries)
    """
    tasks = []
    results = []

    async def worker(s, e):
        async with semaphore:
            entries = await fetch_entries_range(session, s, e)
            if entries:
                results.extend([{"index": s + i, "entry": ent} for i, ent in enumerate(entries)])
            # si None, on ignore — on loggue déjà dans fetch_entries_range

    # découpage en batches
    for s in range(shard_start, shard_end, BATCH_SIZE):
        e = min(s + BATCH_SIZE - 1, shard_end - 1)
        tasks.append(asyncio.create_task(worker(s, e)))

    if tasks:
        await asyncio.gather(*tasks)
    return results

# === Main ===
async def main():
    state = load_state()
    start_index = state.get("next_index", 0)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    async with aiohttp.ClientSession(timeout=REQUEST_TIMEOUT) as session:
        tree_size = await get_tree_size(session)
        if tree_size is None:
            logging.error("Impossible d'obtenir tree_size — arrêt.")
            return

        sem = asyncio.Semaphore(CONCURRENCY)

        while start_index < min(tree_size, 1_000):
            shard_id = start_index // SHARD_SIZE
            shard_dir = OUTPUT_DIR / f"shard_{shard_id:04d}"
            shard_dir.mkdir(parents=True, exist_ok=True)

            shard_end = min(start_index + SHARD_SIZE, tree_size, 1_000)
            logging.info(f"Téléchargement shard {shard_id} [{start_index}–{shard_end})")

            # fetch shard in batches
            entries = await fetch_shard(session, start_index, shard_end, sem)

            if not entries:
                logging.warning(f"Aucune entrée récupérée pour shard {shard_id} [{start_index}-{shard_end}) — avancer et continuer")
                # avancer quand même pour éviter boucle infinie
                start_index = shard_end
                state["next_index"] = start_index
                save_state(state)
                continue

            # écriture gzip JSONL (on écrit les "entry" bruts)
            output_file = shard_dir / f"certs_{start_index:08d}_{shard_end:08d}.jsonl.gz"
            with gzip.open(output_file, "wt", encoding="utf-8") as gz:
                # entries peut être hors d'ordre selon l'assemblage, on trie par index
                entries_sorted = sorted(entries, key=lambda x: x["index"])
                for e in entries_sorted:
                    # e['entry'] est l'objet retourné par l'API (leaf_input, extra_data ...)
                    out = {"index": e["index"], **e["entry"]}
                    gz.write(json.dumps(out, ensure_ascii=False) + "\n")

            logging.info(f"Shard {shard_id} terminé — {len(entries)} entrées écrites -> {output_file}")
            start_index = shard_end
            state["next_index"] = start_index
            save_state(state)

            # Optional short sleep to be gentil avec le serveur
            await asyncio.sleep(0.1)

        logging.info("Fin du téléchargement (atteint tree_size ou 1_000_000)")

if __name__ == "__main__":
    asyncio.run(main())
