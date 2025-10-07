import requests
import base64
import os
from cryptography import x509
from cryptography.hazmat.primitives import serialization

# === Paramètres ===
LOG_URL = "https://ct.googleapis.com/logs/us1/argon2026h1"
OUT_DIR = "./data/raw/"
os.makedirs(OUT_DIR, exist_ok=True)

# === 1. Récupérer 2 entrées depuis le log ===
def get_entries(start=0, end=1):
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
        if field not in entry:
            continue
        blob_b64 = entry[field]
        if not blob_b64:
            continue
        blob = base64.b64decode(blob_b64)
        # Heuristique simple : essayer de parser le blob complet
        try:
            cert = x509.load_der_x509_certificate(blob)
            certs.append(cert)
            continue
        except Exception:
            pass
        # Sinon essayer de découper (le blob peut contenir plusieurs certs)
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
    print(f"Fetching first 2 entries from {LOG_URL} ...")
    entries = get_entries(0, 1)
    print(f"Received {len(entries)} entries.")
    total_saved = 0

    for i, e in enumerate(entries):
        certs = extract_certs_from_entry(e)
        for j, cert in enumerate(certs):
            path = save_pem(cert, i, j)
            print(f"[{path}]")
            print("  Subject:", cert.subject.rfc4514_string())
            print("  Issuer :", cert.issuer.rfc4514_string())
            total_saved += 1

    print(f"\n✅ Done. Saved {total_saved} certificate(s) in '{OUT_DIR}/'.")

if __name__ == "__main__":
    main()