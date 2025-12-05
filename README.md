# CT_RSA

.\.venv\Scripts\Activate.ps1

python et le nom du fichier

pour fetch_ct.py || python fetch_ct.py

deactivate

Certificats, web et calculs de clés privées
— Récupérer au moins 1 million de certificats en utilisant Certificate Transparency en écrivant un crawler
et en téléchargeant les certificats de la PKI Certificate Transparancy utilisant les API publiques
documentées [6]. La liste des API pour récupérer les données est décrite par une RFC. [7]
— Trier les clés par taille
— Recherche de doublons (clés identiques)
— Recherche de clés différentes, mais ayant un facteur commun
— Lancer Batch GCD [1] sur les autres clés, il est possible de trouver soit p soit q commun a une clé
sachant que n = pq
— Bacth GCD existe en Python et en C++, ne pas le recoder !

fetch_ct.py

🧩 1. Objectif global du script

Le but du fichier fetch_ct.py est de télécharger les certificats d’un CT log (Certificate Transparency log), comme Argon2024 de Google.
Ces logs contiennent tous les certificats TLS publics émis dans le monde, sous forme d’entrées numérotées.

Chaque entrée a un index (0, 1, 2, 3, …).
Ce script va donc :

Télécharger les entrées de ce log (de manière efficace).

Les stocker dans des fichiers compressés .jsonl.gz.

Sauvegarder sa progression dans data/state.json pour pouvoir reprendre là où il s’est arrêté.

🧭 2. Fonctionnement général du script

Voici les étapes globales :

Charger la position du dernier téléchargement (dans state.json).

Créer un dossier de sortie data/raw/shard_xxxx.

Télécharger les certificats (en parallèle, avec plusieurs connexions).

Sauvegarder les certificats compressés (.jsonl.gz).

Enregistrer le nouvel index dans state.json.

Recommencer avec le shard suivant, jusqu’à 1 million.

🧠 3. Décomposition du code

Je vais t’expliquer section par section :

🧱 En-tête et imports
import asyncio
import aiohttp
import json
import gzip
import os
import logging
from pathlib import Path

asyncio : permet d’exécuter plusieurs téléchargements en parallèle sans bloquer.

aiohttp : bibliothèque HTTP asynchrone (très rapide).

json, gzip : pour sauvegarder les données dans un format compressé.

logging : pour enregistrer les logs d’exécution.

Path : facilite la manipulation des chemins de fichiers.

⚙️ Paramètres de configuration
CT_LOG_URL = "https://ct.googleapis.com/logs/argon2024"
SHARD_SIZE = 10_000
CONCURRENCY = 10
STATE_FILE = Path("data/state.json")
OUTPUT_DIR = Path("data/raw")
LOG_FILE = Path("data/logs/fetch.log")
TIMEOUT = aiohttp.ClientTimeout(total=30)

CT_LOG_URL : l’URL du log CT à interroger (ici Argon2024 de Google).

SHARD_SIZE : nombre d’entrées à regrouper dans un "shard" (bloc de fichiers).
→ chaque shard = un paquet de 10 000 certificats.

CONCURRENCY : nombre de téléchargements simultanés (10 en parallèle).

STATE_FILE : fichier où on enregistre la progression (data/state.json).

OUTPUT_DIR : dossier où sont stockés les résultats (data/raw/).

LOG_FILE : fichier de log (data/logs/fetch.log).

TIMEOUT : limite de temps (30 s max par requête HTTP).

🧮 Gestion de l’état
def load_state():
if STATE_FILE.exists():
with open(STATE_FILE, "r") as f:
return json.load(f)
return {"next_index": 0}

def save_state(state):
STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
with open(STATE_FILE, "w") as f:
json.dump(state, f)

➡️ Ces deux fonctions gèrent la reprise automatique :

load_state() lit le fichier state.json pour savoir à quel index reprendre.

save_state() enregistre l’index courant (pour relancer plus tard).

Exemple :
si ton script s’arrête à 50 000, quand tu relances, il reprendra à 50 000.

🌐 Téléchargement d’une entrée individuelle
async def fetch_entry(session, index):
url = f"{CT_LOG_URL}/ct/v1/get-entries?start={index}&end={index}"
try:
async with session.get(url) as resp:
if resp.status == 200:
data = await resp.json()
return data["entries"][0]
else:
logging.warning(f"Erreur HTTP {resp.status} pour index {index}")
except Exception as e:
logging.error(f"Exception à l'index {index}: {e}")
return None

Cette fonction :

Télécharge une entrée unique (certificat) du CT log, à l’index donné.

Si la requête réussit (status 200), elle renvoie le contenu JSON.

Sinon, elle logue une erreur et retourne None.

async def → cela veut dire que cette fonction est asynchrone :
elle peut tourner en même temps que d’autres (parallélisme).

⚡ Téléchargement d’un bloc complet
async def fetch_block(session, start, end):
results = []
sem = asyncio.Semaphore(CONCURRENCY)

    async def worker(i):
        async with sem:
            entry = await fetch_entry(session, i)
            if entry:
                results.append({
                    "index": i,
                    "leaf_input": entry.get("leaf_input"),
                    "extra_data": entry.get("extra_data")
                })

    await asyncio.gather(*[worker(i) for i in range(start, end)])
    return results

Cette fonction télécharge tous les certificats d’un bloc [start, end) :

Crée une sémaphore pour limiter à CONCURRENCY (10 tâches en même temps).

Lance une tâche worker() pour chaque index.

asyncio.gather() exécute tout en parallèle.

Chaque entry est stockée dans results.

👉 Ce bloc est le cœur du parallélisme :
il permet de télécharger rapidement des milliers d’entrées sans saturer le serveur.

🚀 Fonction principale
async def main():
state = load_state()
start_index = state["next_index"]
Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)

    async with aiohttp.ClientSession(timeout=TIMEOUT) as session:
        while True:
            shard_id = start_index // SHARD_SIZE
            shard_dir = OUTPUT_DIR / f"shard_{shard_id:04d}"
            shard_dir.mkdir(parents=True, exist_ok=True)
            end_index = start_index + SHARD_SIZE

            logging.info(f"Téléchargement shard {shard_id} [{start_index}–{end_index})")
            block = await fetch_block(session, start_index, end_index)

            if not block:
                logging.warning("Aucune donnée reçue, arrêt.")
                break

            output_file = shard_dir / f"certs_{start_index:08d}_{end_index:08d}.jsonl.gz"
            with gzip.open(output_file, "wt", encoding="utf-8") as gz:
                for entry in block:
                    gz.write(json.dumps(entry) + "\n")

            logging.info(f"Shard {shard_id} terminé — {len(block)} entrées")
            start_index = end_index
            state["next_index"] = start_index
            save_state(state)

            if start_index >= 1_000_000:
                logging.info("Objectif 1M atteint, arrêt.")
                break

C’est le chef d’orchestre :

Charge la position du dernier téléchargement.

Crée un client HTTP (session).

Tant qu’on n’a pas atteint 1M :

Calcule quel shard on traite (0000, 0001, …).

Télécharge les entrées du bloc (fetch_block).

Écrit le résultat dans un fichier compressé .jsonl.gz.

Met à jour state.json avec la nouvelle position.

Passe au shard suivant.

Chaque fichier de sortie contiendra 10 000 lignes JSON, compressées.

🏁 Point d’entrée du programme
if **name** == "**main**":
asyncio.run(main())

➡️ Cela lance la fonction main() dans la boucle asynchrone asyncio.

🔄 4. Ce qu’il se passe quand tu exécutes le code

Quand tu tapes :

python fetch_ct.py

Voici ce qui se passe étape par étape :

Le script lit data/state.json (ou crée un nouvel état {next_index: 0}).

Il se connecte au log CT https://ct.googleapis.com/logs/argon2024.

Il commence à télécharger les certificats à partir de l’index 0.

Il lance 10 téléchargements simultanés en boucle jusqu’à 10 000 (le premier shard).

Les résultats sont enregistrés dans :

data/raw/shard_0000/certs_00000000_00010000.jsonl.gz

Puis il met à jour :

data/state.json → {"next_index": 10000}

Ensuite il télécharge le shard suivant :

shard_0001 : 10000 à 20000

Et ainsi de suite jusqu’à 1 million.

Si tu arrêtes le script, puis le relances, il reprend exactement à la dernière position.

📦 Exemple concret de fichier de sortie

Un fichier .jsonl.gz contient du JSON compressé ligne par ligne.
Chaque ligne correspond à une entrée du CT log :

{"index": 12345, "leaf_input": "MII...", "extra_data": "MII..."}
{"index": 12346, "leaf_input": "MII...", "extra_data": "MII..."}
...

Ce sont les certificats codés en base64.
Ton script parse_cert.py servira ensuite à extraire les vraies clés RSA à partir de ces données.

parse_cert.py

🧭 1. Objectif de parse_cert.py

Le script :

Lit les fichiers produits par fetch_ct.py (data/raw/shard_xxxx/\*.jsonl.gz),

Décode les champs leaf_input et extra_data (base64) pour reconstruire les certificats X.509,

Extrait la clé publique RSA (modulus n, exposant e, taille),

Calcule un hash SHA-256 du modulus pour détecter les doublons,

Enregistre tout dans un fichier Parquet (data/parsed/certs.parquet), format rapide et compressé.

🧩 2. Schéma de données de sortie

Chaque ligne (une clé) contiendra :

Champ###################Type########Description

index###################int#########Index du certificat dans le CT log
key_size################int#########Taille en bits de la clé RSA
exponent################int#########Exposant public
modulus_hex#############str#########Modulus (clé publique) en hexadécimal
modulus_sha256##########str#########Hash SHA-256 du modulus
subject#################str#########Nom du propriétaire du certificat
issuer##################str#########Autorité émettrice
not_before##############str#########Date de début de validité
not_after###############str#########Date de fin de validité
shard###################str#########Nom du shard d’origine
