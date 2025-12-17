#!/usr/bin/env python3
"""
analyze_sample.py — Analyse Rapide pour Démo
- Vérifie les doublons sur 100% des clés (Rapide)
- Attaque GCD sur un échantillon aléatoire (ex: 5000 clés) pour finir en < 2 min
"""

import math
import json
import random
import polars as pl
from pathlib import Path
from datetime import datetime
from collections import defaultdict

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# --- CONFIGURATION DÉMO ---
# Nombre de clés à tester pour le GCD (Max conseillé en Python : 5000 à 10000)
SAMPLE_SIZE = 5000 

def gcd_attack_simple(moduli):
    """O(N^2) mais acceptable sur < 5000 items"""
    factors = defaultdict(list)
    n = len(moduli)
    print(f"   [Calcul] Comparaison de {n} clés entre elles (~{n*n//2} opérations)...")
    
    comparisons = 0
    start = datetime.now()
    
    # Barre de progression maison
    step = n // 10
    
    for i in range(n):
        if i % step == 0 and i > 0:
            elapsed = (datetime.now() - start).total_seconds()
            speed = comparisons / elapsed if elapsed > 0 else 0
            print(f"    -> {i}/{n} ({int(i/n*100)}%) - Vitesse: {int(speed)}/s")

        for j in range(i + 1, n):
            n1, n2 = moduli[i], moduli[j]
            if n1 == n2: continue # Doublons déjà vus
            
            comparisons += 1
            g = math.gcd(n1, n2)
            
            if g > 1:
                factors[g].append((n1, n2))
                
    return factors

def main():
    print("="*60)
    print(" ANALYSE DE SÉCURITÉ RSA (MODE DÉMO)")
    print("="*60)

    # 1. CHARGEMENT
    parsed_dir = PROJECT_ROOT / "data" / "parsed"
    print(f"1. Chargement des données...")
    try:
        df = pl.read_parquet(parsed_dir / "*.parquet")
        total_keys = len(df)
        print(f"   OK : {total_keys} clés chargées.")
    except Exception as e:
        print(f"   Erreur : {e}")
        return

    # 2. DOUBLONS (Sur tout le dataset car c'est rapide)
    print("\n2. Analyse des Doublons (Sur 100% des clés)...")
    unique_df = df.unique(subset=["modulus_hex"])
    unique_count = len(unique_df)
    duplicates = total_keys - unique_count
    
    if duplicates > 0:
        print(f"   [!!!] ALERTE ROUGE : {duplicates} doublons trouvés !")
        print(f"   Ces clés sont trivialement cassables (entropie nulle).")
    else:
        print("   Aucun doublon trouvé.")

    # 3. BATCH GCD (Sur échantillon)
    print(f"\n3. Attaque Batch GCD (Sur échantillon de {SAMPLE_SIZE} clés)...")
    print("   (Note : Faire ça sur 1M de clés prendrait > 10h en Python)")
    
    # On prend un échantillon aléatoire
    if unique_count > SAMPLE_SIZE:
        sample_df = unique_df.sample(n=SAMPLE_SIZE, seed=42)
    else:
        sample_df = unique_df
        
    moduli_int = [int(h, 16) for h in sample_df["modulus_hex"].to_list()]
    
    # Lancement attaque
    vulnerable_factors = gcd_attack_simple(moduli_int)
    
    # RAPPORT RAPIDE
    print("\n" + "="*60)
    print(" RÉSULTATS")
    print("="*60)
    print(f" Doublons (Global)      : {duplicates}")
    print(f" Clés testées GCD       : {len(moduli_int)}")
    print(f" Facteurs communs trouvés : {len(vulnerable_factors)}")
    
    if vulnerable_factors:
        print("\n [!!!] VULNÉRABILITÉ GCD DÉTECTÉE SUR L'ÉCHANTILLON !")
        for f, pairs in list(vulnerable_factors.items())[:5]:
            print(f"   - Facteur {str(f)[:20]}... partagé par {len(pairs)} paires")
    else:
        print("\n [RAS] Aucune vulnérabilité GCD sur cet échantillon.")

    # Sauvegarde JSON
    out_file = PROJECT_ROOT / "data" / "results" / "demo_report.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    
    report = {
        "duplicates_global": duplicates,
        "sample_size": SAMPLE_SIZE,
        "gcd_vulnerabilities": len(vulnerable_factors),
        "details": [
            {"factor": str(f), "count": len(p)} for f, p in vulnerable_factors.items()
        ]
    }
    
    with open(out_file, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n Rapport sauvé : {out_file}")

    # 2.5 ANALYSE DES TAILLES DE CLÉS (Nouveau)
    print("\n2.5 Répartition des tailles de clés RSA...")
    # On groupe par taille de clé et on compte les occurrences
    size_stats = df.group_by("key_size").count().sort("key_size")
    
    for row in size_stats.iter_rows(named=True):
        count = row["count"]
        percent = (count / total_keys) * 100
        print(f"   - {row['key_size']} bits : {count} clés ({percent:.2f}%)")

if __name__ == "__main__":
    main()