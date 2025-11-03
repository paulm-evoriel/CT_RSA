import requests
import base64
import os
import argparse
from cryptography import x509
from cryptography.hazmat.primitives import serialization

# === Paramètres ===
LOG_URL = "https://ct.googleapis.com/logs/us1/argon2026h1"

# Chemin vers le dossier data/raw (un niveau au-dessus de "script")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # -> .../CT_RSA/script/crawler
OUT_DIR = os.path.join(BASE_DIR, "..", "..", "data", "raw")  # -> .../CT_RSA/data/raw
os.makedirs(OUT_DIR, exist_ok=True)

# === 1. Récupérer une plage d’entrées depuis le log ===
def get_entries(start, end):
    url = f"{LOG_URL}/ct/v1/get-entries"
    params = {"start": start, "end": end}
    resp = requests.get(url, params=params, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return data.get("entries", [])

# === 2. Extraire les certificats DER des blobs Base64 ===
def extract_certs_from_entry(entry):
    certs = []
    for field in ("extra_data", "leaf_input"):
        blob_b64 = entry.get(field)
        if not blob_b64:
            continue
        blob = base64.b64decode(blob_b64)
        # Essayer le blob complet
        try:
            cert = x509.load_der_x509_certificate(blob)
            certs.append(cert)
            continue
        except Exception:
            pass
        # Sinon parcourir le blob (peut contenir plusieurs certs)
        i = 0
        while i < len(blob) - 4:
            if blob[i] == 0x30:  # probable début de SEQUENCE ASN.1
                try:
                    cert = x509.load_der_x509_certificate(blob[i:])
                    certs.append(cert)
                    break
                except Exception:
                    pass
            i += 1
    return certs

# === 3. Sauvegarder les certificats au format PEM ===
def save_pem(cert, index, subindex):
    pem = cert.public_bytes(serialization.Encoding.PEM)
    path = os.path.join(OUT_DIR, f"cert_{index}_{subindex}.pem")
    with open(path, "wb") as f:
        f.write(pem)
    return path

# === 4. Programme principal ===
def main():
    parser = argparse.ArgumentParser(description="Télécharge des certificats depuis le log CT de Google.")
    parser.add_argument("--count", type=int, default=2, help="Nombre de certificats à récupérer (défaut: 2)")
    args = parser.parse_args()

    count = args.count
    print(f"Fetching first {count} entries from {LOG_URL} ...")

    total_saved = 0
    batch_size = 1000  # on limite les requêtes par lot (API CT n’aime pas les grandes plages)
    start = 0

    while total_saved < count:
        end = min(start + batch_size - 1, start + (count - total_saved) - 1)
        entries = get_entries(start, end)
        print(f"➡️ Fetched entries {start} to {end} ({len(entries)} entries)")

        for i, e in enumerate(entries, start=start):
            certs = extract_certs_from_entry(e)
            for j, cert in enumerate(certs):
                path = save_pem(cert, i, j)
                print(f"[{path}]")
                print("  Subject:", cert.subject.rfc4514_string())
                print("  Issuer :", cert.issuer.rfc4514_string())
                total_saved += 1
                if total_saved >= count:
                    break
            if total_saved >= count:
                break

        start = end + 1

    print(f"\n✅ Done. Saved {total_saved} certificate(s) in '{OUT_DIR}/'.")

if __name__ == "__main__":
    main()
