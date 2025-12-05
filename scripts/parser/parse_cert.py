#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
parse_cert.py — version scalable
Lit les fichiers .jsonl.gz produits par fetch_ct.py,
extrait les clés RSA et les enregistre dans un fichier Parquet.
"""

import os
import gzip
import json
import base64
import hashlib
import logging
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import polars as pl  # rapide, compatible parquet

# === Configuration ===
RAW_DIR = Path("data/raw")
OUTPUT_DIR = Path("data/parsed")
OUTPUT_FILE = OUTPUT_DIR / "certs.parquet"
LOG_FILE = Path("data/logs/parse.log")

# === Logging ===
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# === Utils ===
def modulus_sha256(n: int) -> str:
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return hashlib.sha256(b).hexdigest()

def safe_b64decode(data: str) -> bytes:
    """Corrige le padding Base64 si nécessaire."""
    data += '=' * (-len(data) % 4)
    return base64.b64decode(data)

def parse_certificate_from_entry(entry: dict):
    """
    Essaie de décoder un certificat X.509 à partir d'une entrée CT.
    Retourne un dict avec les infos importantes, ou None si erreur.
    """
    try:
        extra = safe_b64decode(entry["extra_data"])
        cert = x509.load_der_x509_certificate(extra)

        pubkey = cert.public_key()
        if not isinstance(pubkey, rsa.RSAPublicKey):
            return None  # ignorer non-RSA

        numbers = pubkey.public_numbers()

        return {
            "index": entry["index"],
            "key_size": pubkey.key_size,
            "exponent": numbers.e,
            "modulus_hex": format(numbers.n, "x"),
            "modulus_sha256": modulus_sha256(numbers.n),
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_before": cert.not_valid_before.isoformat(),
            "not_after": cert.not_valid_after.isoformat()
        }
    except Exception as e:
        logging.warning(f"Erreur parsing certificat index {entry.get('index')}: {e}")
        return None

def process_shard(shard_dir: Path):
    """Parse tous les fichiers d’un shard donné."""
    rows = []
    for file in shard_dir.glob("*.jsonl.gz"):
        with gzip.open(file, "rt", encoding="utf-8") as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    parsed = parse_certificate_from_entry(entry)
                    if parsed:
                        parsed["shard"] = shard_dir.name
                        rows.append(parsed)
                except json.JSONDecodeError:
                    logging.error(f"JSON invalide dans {file}")
    return rows

def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    all_rows = []

    shards = sorted(RAW_DIR.glob("shard_*"))
    logging.info(f"Trouvé {len(shards)} shards à traiter")

    for shard in shards:
        logging.info(f"Traitement de {shard}")
        rows = process_shard(shard)
        if rows:
            df = pl.DataFrame(rows)
            # Append Parquet (concaténation incrémentale)
            if OUTPUT_FILE.exists():
                old = pl.read_parquet(OUTPUT_FILE)
                df = pl.concat([old, df])
            df.write_parquet(OUTPUT_FILE, compression="zstd")
            logging.info(f"{len(rows)} certificats ajoutés depuis {shard}")
        else:
            logging.info(f"Aucun certificat RSA dans {shard}")

if __name__ == "__main__":
    main()
