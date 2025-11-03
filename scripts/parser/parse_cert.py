import os
import csv
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# === Chemins relatifs au dossier du script ===
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # -> .../CT_RSA/script/crawler
DATA_DIR = os.path.join(BASE_DIR, "..", "..", "data")  # -> .../CT_RSA/data

RAW_DIR = os.path.join(DATA_DIR, "raw")
OUT_FILE = os.path.join(DATA_DIR, "parsed", "certs_info.csv")

def extract_rsa_info(cert_path):
    try:
        with open(cert_path, "rb") as f:
            data = f.read()
        cert = x509.load_pem_x509_certificate(data, default_backend())
        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            numbers = public_key.public_numbers()
            return {
                "filename": os.path.basename(cert_path),
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "modulus": numbers.n,
                "exponent": numbers.e,
                "key_size": public_key.key_size
            }
    except Exception:
        # Ignore les certificats non RSA ou corrompus
        return None

def main():
    os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)
    cert_files = [f for f in os.listdir(RAW_DIR) if f.endswith(".pem")]
    results = []

    print(f"🔍 Parsing {len(cert_files)} certificats depuis {RAW_DIR} ...")

    for file in cert_files:
        cert_path = os.path.join(RAW_DIR, file)
        info = extract_rsa_info(cert_path)
        if info:
            results.append(info)

    # Sauvegarde au format CSV
    with open(OUT_FILE, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["filename", "subject", "issuer", "modulus", "exponent", "key_size"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"✅ {len(results)} certificats RSA extraits et sauvegardés dans {OUT_FILE}")

if __name__ == "__main__":
    main()
