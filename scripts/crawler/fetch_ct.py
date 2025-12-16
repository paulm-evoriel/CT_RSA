#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fetch_ct.py — version "Robust & Best Effort"
- Ne s'arrête PAS s'il manque des données.
- Prend tout ce que le serveur renvoie et continue.
- Idéal pour récupérer 1M de certs même si le serveur limite la pagination.
"""

import asyncio
import aiohttp
import json
import gzip
import logging
import time
import random
from pathlib import Path

# === Configuration ===
PROJECT_ROOT = Path(__file__).parent.parent.parent

CT_LOG_URL = "https://ct.googleapis.com/logs/eu1/xenon2024"
SHARD_SIZE = 10000          # 1 fichier = 10 000 entrées
BATCH_SIZE = 256            # Requêtes par blocs de 256
CONCURRENCY = 16            # Un peu plus de parallélisme
MAX_RETRIES = 5             # Retries sur erreurs réseau (500, 502...)
TARGET_TOTAL = 1_000_000    # Objectif final

STATE_FILE = PROJECT_ROOT / "data" / "state.json"
OUTPUT_DIR = PROJECT_ROOT / "data" / "raw"
LOG_FILE = PROJECT_ROOT / "logs" / "fetch.log"
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=60) # Timeout large

# Logging
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

# === Helpers État ===
def load_state():
    if STATE_FILE.exists():
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"next_index": 0}

def save_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f)

# === Récupération de la taille de l'arbre ===
async def get_tree_size(session):
    url = f"{CT_LOG_URL}/ct/v1/get-sth"
    for _ in range(3):
        try:
            async with session.get(url) as resp:
                if resp.status == 200:
                    j = await resp.json()
                    return int(j.get("tree_size", 0))
        except Exception as e:
            logging.warning(f"Erreur get-sth: {e}")
            await asyncio.sleep(1)
    return None

# === Fetch d'une plage (Batch) avec Retries Réseau seulement ===
async def fetch_entries_range(session, start, end):
    url = f"{CT_LOG_URL}/ct/v1/get-entries?start={start}&end={end}"
    backoff = 0.5
    
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            logging.debug(f"Req {start}-{end} attempt {attempt} -> {url}")
            async with session.get(url) as resp:
                status = resp.status
                if status == 200:
                    j = await resp.json()
                    entries = j.get("entries", [])
                    logging.debug(f"HTTP 200 {start}-{end}: {len(entries)} entries returned")
                    return entries # On retourne ce qu'on a reçu, même si incomplet
                elif status in [429, 500, 502, 503]:
                    logging.warning(f"HTTP {status} pour {start}-{end}. Retry...")
                else:
                    logging.warning(f"Erreur HTTP {status} pour {start}-{end} - ignoré.")
                    return [] # Erreur non fatale, on renvoie vide
        except Exception as e:
            logging.warning(f"Exception réseau {start}-{end}: {e}")
        
        await asyncio.sleep(backoff)
        backoff = min(backoff * 1.5, 10)
    
    logging.error(f"Abandon batch {start}-{end} après {MAX_RETRIES} essais réseau.")
    return []

# === Fetch d'un SHARD en mode "Best Effort" ===
async def fetch_shard_robust(session, shard_start, shard_end, semaphore):
    """
    Télécharge tout ce qui est possible dans la plage [shard_start, shard_end).
    Ne s'arrête pas si des trous sont détectés.
    """
    tasks = []
    
    # 1. Préparation des tâches
    for s in range(shard_start, shard_end, BATCH_SIZE):
        e = min(s + BATCH_SIZE - 1, shard_end - 1)
        tasks.append((s, e))

    all_entries = [] # Liste plate de toutes les entrées récupérées

    async def worker(s, e):
        async with semaphore:
            # Mode adaptatif : on avance l'index courant de la taille renvoyée
            results = []
            cur = s
            expected = e - s + 1

            while cur <= e:
                # léger jitter pour casser l'alignement des requêtes
                await asyncio.sleep(random.uniform(0, 0.05))
                entries_raw = await fetch_entries_range(session, cur, e)
                if not entries_raw:
                    logging.debug(f"Aucun résultat pour {cur}-{e}, arrêt local du worker")
                    break

                # Ajouter les entrées récupérées en respectant la borne e
                for i, entry_data in enumerate(entries_raw):
                    idx = cur + i
                    if idx > e:
                        break
                    results.append({"index": idx, **entry_data})

                got = len(entries_raw)
                logging.debug(f"Adaptive chunk {cur}-{e}: got {got} (accumulé {len(results)}/{expected})")

                # Avancer
                cur += got

                # Sécurité anti-boucle : si le serveur renvoie 0 (déjà géré) ou ne progresse
                if got == 0:
                    break

            logging.debug(f"Batch adaptatif {s}-{e}: {len(results)}/{expected} reconstruits")
            if len(results) < expected:
                logging.debug(f"Batch partiel adaptatif {s}-{e}: {len(results)}/{expected} reçus (continu...)")

            return results

    # 2. Exécution parallèle
    futures = [asyncio.create_task(worker(s, e)) for s, e in tasks]
    batch_results_list = await asyncio.gather(*futures)

    # 3. Assemblage
    for res in batch_results_list:
        all_entries.extend(res)

    # 4. Tri final par index pour avoir un fichier propre
    all_entries.sort(key=lambda x: x["index"])
    
    return all_entries

# === Main ===
async def main():
    state = load_state()
    start_index = state.get("next_index", 0)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    logging.info(f"Démarrage. Index actuel: {start_index}. Objectif: {TARGET_TOTAL}")

    async with aiohttp.ClientSession(timeout=REQUEST_TIMEOUT) as session:
        tree_size = await get_tree_size(session)
        if not tree_size:
            logging.error("Impossible de contacter le serveur.")
            return
        
        logging.info(f"Taille du log: {tree_size}")
        limit_index = min(tree_size, TARGET_TOTAL)
        
        sem = asyncio.Semaphore(CONCURRENCY)

        while start_index < limit_index:
            shard_end = min(start_index + SHARD_SIZE, limit_index)
            shard_id = start_index // SHARD_SIZE
            
            logging.info(f"Traitement Shard {shard_id} [{start_index}-{shard_end}]...")

            # Récupération (ne renvoie jamais None, au pire une liste partielle)
            entries = await fetch_shard_robust(session, start_index, shard_end, sem)

            count = len(entries)
            expected = shard_end - start_index
            
            if count == 0:
                logging.warning(f"Shard {shard_id} VIDE ! (Réseau HS ou fin du log?). On avance quand même.")
            elif count < expected:
                logging.info(f"Shard {shard_id} incomplet: {count}/{expected} entrées récupérées. Sauvegarde en cours...")
            else:
                logging.info(f"Shard {shard_id} complet ({count} entrées).")

            # Sauvegarde
            output_file = OUTPUT_DIR / f"shard_{shard_id:04d}_{start_index:08d}_{shard_end:08d}.jsonl.gz"
            try:
                with gzip.open(output_file, "wt", encoding="utf-8") as gz:
                    for e in entries:
                        gz.write(json.dumps(e, ensure_ascii=False) + "\n")
                
                # On valide et on passe au suivant
                start_index = shard_end
                state["next_index"] = start_index
                save_state(state)
                
            except Exception as e:
                logging.error(f"Erreur d'écriture disque: {e}")
                break

    logging.info("Script terminé.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Arrêt manuel par l'utilisateur.")