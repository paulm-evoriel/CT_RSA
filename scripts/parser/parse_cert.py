#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
parse_cert.py — Extracteur RSA Correctif Final
"""

import gzip
import json
import base64
import hashlib
import logging
from pathlib import Path
from asn1crypto import x509
import polars as pl

# ================= CONFIG =================

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
RAW_DIR = PROJECT_ROOT / "data" / "raw"
OUTPUT_DIR = PROJECT_ROOT / "data" / "parsed"
LOG_FILE = PROJECT_ROOT / "logs" / "parse_final.log"

# ================= LOGGING =================

LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()],
)

# ================= UTILS =================

# OIDs pour RSA
OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
OID_RSA_PKCS1 = "1.2.840.113549.1.1.11"

def sha256_modulus(n: int) -> str:
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return hashlib.sha256(b).hexdigest()

def extract_rsa_safe(asn1_obj, index_ref):
    """Extrait la clé RSA avec les bons noms de champs asn1crypto."""
    try:
        # 1. On récupère la structure SubjectPublicKeyInfo
        spki = asn1_obj["subject_public_key_info"]
        
        # 2. Vérification de l'algorithme via OID
        algo_oid = spki["algorithm"]["algorithm"].dotted
        if algo_oid not in (OID_RSA_ENCRYPTION, OID_RSA_PKCS1):
            return "ECC"

        # 3. CORRECTION ICI : Le champ s'appelle 'public_key' dans asn1crypto
        # et non 'subject_public_key'
        pub_bits = spki["public_key"].parsed
        
        n = pub_bits["modulus"].native
        e = pub_bits["public_exponent"].native

        return {
            "index": index_ref,
            "key_size": n.bit_length(),
            "exponent": int(e),
            "modulus_hex": format(n, "x"),
            "modulus_sha256": sha256_modulus(n),
        }
    except Exception as e:
        return f"ERROR: {str(e)}"

def robust_parse_line(blob, index):
    # Offset standard CT
    offset = 15
    
    # Sécurité : Si l'offset ne pointe pas sur une séquence, on cherche
    if len(blob) <= offset or blob[offset] != 0x30:
        offset = blob.find(b'\x30\x82')
    
    if offset == -1:
        return None, "NO_ASN1"

    data = blob[offset:]
    
    # Essai 1 : Certificat
    try:
        cert = x509.Certificate.load(data)
        return extract_rsa_safe(cert['tbs_certificate'], index), "CERT"
    except:
        pass

    # Essai 2 : TBS (Pre-cert)
    try:
        tbs = x509.TbsCertificate.load(data)
        return extract_rsa_safe(tbs, index), "TBS"
    except:
        pass

    return None, "PARSE_FAIL"

def process_shard(path: Path):
    rows = []
    stats = {"RSA": 0, "ECC": 0, "FAIL": 0}
    first_error = None
    
    with gzip.open(path, "rt", encoding="utf-8") as f:
        for line in f:
            try:
                entry = json.loads(line)
                if "leaf_input" not in entry: continue
                
                blob = base64.b64decode(entry["leaf_input"])
                result, _ = robust_parse_line(blob, entry["index"])
                
                if isinstance(result, dict):
                    rows.append(result)
                    stats["RSA"] += 1
                elif result == "ECC":
                    stats["ECC"] += 1
                else:
                    stats["FAIL"] += 1
                    if not first_error and isinstance(result, str) and result.startswith("ERROR"):
                        first_error = result

            except Exception:
                stats["FAIL"] += 1
                continue

    return rows, stats, first_error

# ================= MAIN =================

def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    shards = sorted(RAW_DIR.glob("shard_*.jsonl.gz"))
    
    if not shards:
        logging.error("Aucun shard trouve.")
        return

    logging.info(f"Traitement de {len(shards)} shards...")
    total_rsa = 0

    for shard in shards:
        out_path = OUTPUT_DIR / shard.name.replace(".jsonl.gz", ".parquet")
        
        if out_path.exists():
            continue

        logging.info(f"Lecture de {shard.name}...")
        rows, stats, err = process_shard(shard)

        logging.info(f" -> RSA: {stats['RSA']} | ECC: {stats['ECC']} | Fail: {stats['FAIL']}")
        
        if stats['RSA'] == 0 and err:
            logging.error(f" [!] EXEMPLE ERREUR : {err}")

        if rows:
            df = pl.DataFrame(rows)
            df = df.with_columns([
                pl.col("index").cast(pl.UInt64),
                pl.col("key_size").cast(pl.UInt16),
                pl.col("exponent").cast(pl.UInt32),
            ])
            df.write_parquet(out_path, compression="zstd")
            total_rsa += len(rows)

    logging.info(f"--- TERMINE : {total_rsa} RSA extraites ---")

if __name__ == "__main__":
    main()