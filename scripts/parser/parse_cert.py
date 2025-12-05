#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
parse_cert.py — version scalable
Lit les fichiers .jsonl.gz produits par fetch_ct.py,
extrait les cles RSA et les enregistre dans un fichier Parquet.
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
# Calcul du chemin racine du projet (remonte depuis scripts/parser/ vers la racine)
PROJECT_ROOT = Path(__file__).parent.parent.parent

RAW_DIR = PROJECT_ROOT / "data" / "raw"
OUTPUT_DIR = PROJECT_ROOT / "data" / "parsed"
OUTPUT_FILE = OUTPUT_DIR / "certs.parquet"
LOG_FILE = PROJECT_ROOT / "logs" / "parse.log"

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
    """Corrige le padding Base64 si necessaire."""
    data += '=' * (-len(data) % 4)
    return base64.b64decode(data)

def parse_certificate_from_entry(entry: dict):
    """
    Essaie de decoder un certificat X.509 a partir d'une entree CT.
    Pour X509Entry, le certificat est dans extra_data (format TLS certificate_list).
    Format extra_data pour X509Entry:
    - 3 bytes: longueur totale
    - 3 bytes: longueur de la certificate_list
    - Pour chaque certificat: 3 bytes (longueur) + certificat DER
    Retourne un dict avec les infos importantes, ou None si erreur.
    """
    try:
        # Decoder extra_data qui contient la chaîne de certificats
        extra_data = safe_b64decode(entry["extra_data"])
        
        if len(extra_data) < 6:
            return None
        
        # Format TLS Certificate: 
        # - 3 bytes: longueur totale (uint24)
        # - 3 bytes: longueur de la certificate_list (uint24)
        # - Les certificats suivent directement en DER (sans prefixe de longueur individuelle)
        total_length = int.from_bytes(extra_data[0:3], byteorder='big')
        cert_list_length = int.from_bytes(extra_data[3:6], byteorder='big')
        
        if len(extra_data) < 6 + cert_list_length:
            return None
        
        # Le premier certificat commence a l'offset 6
        # Les certificats sont en format DER directement (pas de prefixe de longueur)
        # Le format DER commence par 0x30 (SEQUENCE)
        offset = 6
        
        if offset >= len(extra_data):
            return None
        
        # Le certificat DER commence directement ici
        # On doit parser la longueur depuis le format ASN.1 DER
        if extra_data[offset] != 0x30:  # SEQUENCE tag
            return None
        
        # Parser la longueur ASN.1 DER pour obtenir la taille complète du certificat
        cert_start = offset
        offset += 1  # Skip SEQUENCE tag (0x30)
        
        if offset >= len(extra_data):
            return None
        
        # Lire la longueur (peut être sur 1, 2, 3 ou 4 bytes selon ASN.1)
        length_byte = extra_data[offset]
        offset += 1
        
        if length_byte & 0x80 == 0:
            # Longueur courte (1 byte)
            cert_content_length = length_byte
            length_header_size = 1
        else:
            # Longueur longue (plusieurs bytes)
            length_bytes_count = length_byte & 0x7F
            if length_bytes_count == 0 or length_bytes_count > 4:
                return None
            if offset + length_bytes_count > len(extra_data):
                return None
            cert_content_length = int.from_bytes(extra_data[offset:offset+length_bytes_count], byteorder='big')
            offset += length_bytes_count
            length_header_size = 1 + length_bytes_count
        
        # Le certificat complet = tag (1) + longueur header (1-5) + contenu
        cert_total_length = 1 + length_header_size + cert_content_length
        
        # Extraire le certificat DER complet
        if cert_start + cert_total_length > len(extra_data):
            return None
        
        cert_der = extra_data[cert_start:cert_start + cert_total_length]
        
        if len(cert_der) == 0:
            return None
        
        # Decoder le certificat X.509
        cert = x509.load_der_x509_certificate(cert_der)

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
    """Parse tous les fichiers d’un shard donne."""
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
    logging.info(f"Trouve {len(shards)} shards a traiter")

    for shard in shards:
        logging.info(f"Traitement de {shard}")
        rows = process_shard(shard)
        if rows:
            df = pl.DataFrame(rows)
            # Append Parquet (concatenation incrementale)
            if OUTPUT_FILE.exists():
                old = pl.read_parquet(OUTPUT_FILE)
                df = pl.concat([old, df])
            df.write_parquet(OUTPUT_FILE, compression="zstd")
            logging.info(f"{len(rows)} certificats ajoutes depuis {shard}")
        else:
            logging.info(f"Aucun certificat RSA dans {shard}")

if __name__ == "__main__":
    main()
