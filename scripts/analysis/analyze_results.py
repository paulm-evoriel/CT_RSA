#!/usr/bin/env python3
"""
Script d'analyse Batch GCD pour CT_RSA
- Trie les cles par taille
- Recherche de doublons (cles identiques)
- Recherche de facteurs communs via Batch GCD
- Version sans indices dans le rapport JSON
"""

import gzip
import json
import math
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from typing import List, Tuple, Dict

# Calcul du chemin racine du projet
PROJECT_ROOT = Path(__file__).parent.parent.parent

def batch_gcd_simple(moduli: List[int]) -> Dict[int, List[Tuple[int, int]]]:
    """
    Batch GCD simple : compare toutes les paires de modulus.
    Retourne un dict {facteur_commun: [(n1, n2), ...]}
    """
    common_factors = defaultdict(list)
    
    print(f"  Calcul Batch GCD sur {len(moduli)} modulus...")
    
    for i in range(len(moduli)):
        if (i + 1) % 100 == 0:
            print(f"      Progression: {i+1}/{len(moduli)}")
        
        for j in range(i + 1, len(moduli)):
            n1, n2 = moduli[i], moduli[j]
            if n1 == n2:
                continue  # Doublons dej detectes
            
            gcd = math.gcd(n1, n2)
            if gcd > 1:  # Facteur commun trouve !
                common_factors[gcd].append((n1, n2))
    
    return dict(common_factors)

def batch_gcd_tree(moduli: List[int]) -> Dict[int, List[Tuple[int, int]]]:
    """
    Batch GCD optimise avec arbre binaire (plus efficace pour grand nombre).
    Retourne un dict {facteur_commun: [(n1, n2), ...]}
    """
    if len(moduli) < 100:
        return batch_gcd_simple(moduli)
    
    print(f"  Calcul Batch GCD optimise (arbre) sur {len(moduli)} modulus...")
    
    # Construire l'arbre de produits
    def build_product_tree(nums):
        """Construit un arbre de produits pour calculer efficacement les GCD"""
        if len(nums) == 1:
            return nums[0]
        
        products = []
        for i in range(0, len(nums), 2):
            if i + 1 < len(nums):
                products.append(nums[i] * nums[i + 1])
            else:
                products.append(nums[i])
        
        return build_product_tree(products)
    
    # Calculer le produit de tous les modulus
    try:
        root_product = build_product_tree(moduli)
    except OverflowError:
        # Si overflow, utiliser methode simple
        return batch_gcd_simple(moduli)
    
    # Pour chaque modulus, calculer GCD avec le produit
    common_factors = defaultdict(list)
    
    for i, n in enumerate(moduli):
        if (i + 1) % 100 == 0:
            print(f"      Progression: {i+1}/{len(moduli)}")
        
        # Calculer GCD(n, root_product / n)
        # Pour eviter de diviser, on calcule GCD(n, root_product) qui peut reveler des facteurs
        gcd = math.gcd(n, root_product // n if root_product > n else root_product)
        
        if gcd > 1 and gcd < n:  # Facteur commun trouve
            # Trouver les autres modulus qui partagent ce facteur
            for j, m in enumerate(moduli):
                if i != j:
                    pair_gcd = math.gcd(n, m)
                    if pair_gcd > 1:
                        common_factors[pair_gcd].append((n, m))
    
    return dict(common_factors)

def analyze_rsa_keys(df):
    """
    Analyse complète des cles RSA :
    1. Tri par taille
    2. Recherche de doublons
    3. Batch GCD pour facteurs communs
    """
    import polars as pl
    
    print("\n" + "=" * 70)
    print("ANALYSE CRYPTOGRAPHIQUE DES CLeS RSA")
    print("=" * 70)
    
    if len(df) == 0:
        print("  Aucun certificat RSA a analyser")
        return
    
    # 1. TRIER LES CLeS PAR TAILLE
    print("\n1️  TRI DES CLeS PAR TAILLE")
    print("-" * 70)
    df_sorted = df.sort("key_size")
    
    key_sizes = df_sorted["key_size"].unique().to_list()
    print(f"   Tailles de cles trouvees: {sorted(key_sizes)}")
    
    for size in sorted(key_sizes):
        count = len(df_sorted.filter(pl.col("key_size") == size))
        print(f"   - {size} bits: {count} certificats")
    
    # 2. RECHERCHE DE DOUBLONS (MÊME MODULUS)
    print("\n2️  RECHERCHE DE DOUBLONS (CLeS IDENTIQUES)")
    print("-" * 70)
    
    # Compter les modulus uniques
    unique_moduli = df["modulus_sha256"].n_unique()
    total_certs = len(df)
    duplicates = total_certs - unique_moduli
    
    print(f"   Total certificats: {total_certs}")
    print(f"   Modulus uniques: {unique_moduli}")
    print(f"   Doublons detectes: {duplicates}")
    
    if duplicates > 0:
        print(f"\n    ATTENTION: {duplicates} certificats ont le même modulus !")
        # Trouver les doublons exacts
        duplicates_df = df.group_by("modulus_sha256", maintain_order=True).agg([
            pl.len().alias("count"),
            pl.col("index").alias("indices"),
            pl.col("subject").alias("subjects")
        ]).filter(pl.col("count") > 1)
        
        print(f"\n   Details des doublons:")
        for row in duplicates_df.iter_rows(named=True):
            modulus_hash = str(row['modulus_sha256'])
            indices = row['indices']
            if not isinstance(indices, list):
                indices = list(indices) if hasattr(indices, '__iter__') else [indices]
            count = row['count']
            print(f"      - Modulus SHA256: {modulus_hash[:16]}...")
            print(f"        Apparu {count} fois aux indices: {indices[:5]}")
    
    # 3. BATCH GCD - RECHERCHE DE FACTEURS COMMUNS
    print("\n3️  BATCH GCD - RECHERCHE DE FACTEURS COMMUNS")
    print("-" * 70)
    
    # Convertir les modulus hex en entiers
    print("    Conversion des modulus hex en entiers...")
    moduli = []
    modulus_to_index = {}  # On garde ça pour l'affichage console uniquement
    
    for idx, row in enumerate(df.iter_rows(named=True)):
        try:
            n = int(row["modulus_hex"], 16)
            moduli.append(n)
            modulus_to_index[n] = row["index"]
        except (ValueError, KeyError) as e:
            continue
    
    print(f"   {len(moduli)} modulus convertis")
    
    if len(moduli) < 2:
        print("    Pas assez de modulus pour Batch GCD (minimum 2)")
        return
    
    # Lancer Batch GCD
    common_factors = batch_gcd_simple(moduli)
    
    # Calculer les statistiques complètes
    total_certs_with_duplicates = sum(row['count'] for row in duplicates_df.iter_rows(named=True)) if duplicates > 0 else 0
    unique_certs = unique_moduli
    vulnerable_from_factors = sum(len(pairs) * 2 for pairs in common_factors.values()) if common_factors else 0
    
    # Certificats sûrs = total - doublons - vulnérables par facteurs communs
    # (en comptant chaque occurrence de doublon comme vulnérable)
    safe_certs = unique_certs - len(common_factors) if common_factors else unique_certs
    unsafe_certs = (total_certs - unique_certs) + vulnerable_from_factors
    
    # Preparer le fichier de sauvegarde (toujours sauvegarder, même sans facteurs communs)
    results_file = PROJECT_ROOT / "data" / "results" / "vulnerable_keys.json"
    results_file.parent.mkdir(parents=True, exist_ok=True)
    
    if common_factors:
        print(f"\n     VULNeRABILITe DeTECTeE: {len(common_factors)} facteurs communs trouves !")
        print(f"\n   Details des facteurs communs:")
        
        vulnerable_count = 0
        common_factors_details = {}
        for factor, pairs in common_factors.items():
            print(f"\n      Facteur commun: {factor}")
            print(f"      Nombre de paires affectees: {len(pairs)}")
            
            # Afficher quelques exemples en console (avec indices pour debug)
            for n1, n2 in pairs[:3]:
                idx1 = modulus_to_index.get(n1, "?")
                idx2 = modulus_to_index.get(n2, "?")
                print(f"         - Indices {idx1} et {idx2} partagent ce facteur")
                vulnerable_count += 2
            
            # === MODIFICATION : Suppression des indices dans le JSON ===
            common_factors_details[str(factor)] = [
                {
                    "n1": str(n1), 
                    "n2": str(n2)
                    # "index1" et "index2" supprimés ici
                }
                for n1, n2 in pairs
            ]
        
        print(f"\n   TOTAL: {vulnerable_count} certificats potentiellement compromis")
    else:
        print("\n   Aucun facteur commun detecte - toutes les cles semblent sûres")
        common_factors_details = {}
    
    # Préparer les détails des doublons
    duplicates_details = []
    if duplicates > 0:
        for row in duplicates_df.iter_rows(named=True):
            modulus_hash = str(row['modulus_sha256'])
            # On récupère les indices pour le calcul du count, mais on ne les stocke pas
            count = row['count']
            
            # === MODIFICATION : Suppression des indices dans le JSON ===
            duplicates_details.append({
                "modulus_sha256": modulus_hash,
                "occurrences": count,
                # "indices": ... supprimé ici
                "affected_certificates": count
            })
    
    # Créer le rapport complet
    results = {
        "analysis_metadata": {
            "analysis_date": datetime.now().isoformat(),
            "analysis_version": "1.0"
        },
        "analysis_summary": {
            "total_certificates_analyzed": total_certs,
            "unique_modulus_count": unique_moduli,
            "duplicate_modulus_count": duplicates,
            "common_factors_found": len(common_factors) if common_factors else 0,
            "status": "vulnerable" if (common_factors or duplicates > 0) else "safe"
        },
        "security_statistics": {
            "safe_certificates": safe_certs,
            "unsafe_certificates": unsafe_certs,
            "safe_ratio": round((safe_certs / total_certs * 100), 2) if total_certs > 0 else 0,
            "unsafe_ratio": round((unsafe_certs / total_certs * 100), 2) if total_certs > 0 else 0,
            "vulnerable_from_duplicates": duplicates,
            "vulnerable_from_common_factors": vulnerable_from_factors,
            "total_vulnerable": unsafe_certs
        },
        "key_size_distribution": {
            "unique_sizes": sorted(key_sizes),
            "distribution": {
                str(size): int(len(df_sorted.filter(pl.col("key_size") == size)))
                for size in sorted(key_sizes)
            }
        },
        "duplicates_analysis": {
            "total_duplicates": duplicates,
            "duplicate_ratio": round((duplicates / total_certs * 100), 2) if total_certs > 0 else 0,
            "unique_modulus_ratio": round((unique_moduli / total_certs * 100), 2) if total_certs > 0 else 0,
            "details": duplicates_details
        },
        "common_factors_analysis": {
            "total_common_factors": len(common_factors) if common_factors else 0,
            "affected_certificates": vulnerable_from_factors,
            "details": common_factors_details
        },
        "recommendations": {
            "revoke_certificates": duplicates > 0 or common_factors is not None,
            "regenerate_keys": duplicates > 0 or common_factors is not None,
            "investigate_root_cause": duplicates > 10 or (common_factors and len(common_factors) > 0)
        }
    }
    
    # Sauvegarder dans tous les cas
    with open(results_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"\n   Resultats sauvegardes dans: {results_file}")
    
    # 4. ReSUMe
    print("\n" + "=" * 70)
    print("ReSUMe DE L'ANALYSE")
    print("=" * 70)
    print(f"   Total certificats analyses: {total_certs}")
    print(f"   Tailles de cles: {sorted(key_sizes)}")
    print(f"   Doublons (même modulus): {duplicates}")
    print(f"   Facteurs communs trouves: {len(common_factors)}")
    if common_factors:
        total_vulnerable = sum(len(pairs) * 2 for pairs in common_factors.values())
        print(f"   Certificats potentiellement compromis: {total_vulnerable}")

def main():
    print("=" * 70)
    print("ANALYSE DES ReSULTATS - CT_RSA")
    print("=" * 70)
    
    # Compter les entrees brutes
    raw_dir = PROJECT_ROOT / "data" / "raw"
    total_entries = 0
    if raw_dir.exists():
        for shard_dir in sorted(raw_dir.glob("shard_*")):
            for file in shard_dir.glob("*.jsonl.gz"):
                try:
                    with gzip.open(file, "rt", encoding="utf-8") as f:
                        count = sum(1 for _ in f)
                        total_entries += count
                        print(f"\n {shard_dir.name}/{file.name}: {count} entrees")
                except Exception as e:
                    print(f"Erreur lecture {file}: {e}")

    print(f"\n TOTAL ENTRIES TeLeCHARGeES: {total_entries}")
    
    # Charger et analyser les certificats RSA parses
    parsed_file = PROJECT_ROOT / "data" / "parsed" / "certs.parquet"
    if parsed_file.exists():
        try:
            import polars as pl
            df = pl.read_parquet(parsed_file)
            rsa_count = len(df)
            print(f" CERTIFICATS RSA EXTRITS: {rsa_count}")
            print(f"\n DIFFeRENCE: {total_entries - rsa_count} entrees non-RSA ou invalides")
            if total_entries > 0:
                print(f"   ({((rsa_count / total_entries) * 100):.1f}% sont des certificats RSA)")
            
            if rsa_count > 0:
                # Lancer l'analyse complète
                analyze_rsa_keys(df)
        except ImportError:
            print("  Polars non installe, impossible d'analyser les certificats parses")
            print("   Installez avec: pip install polars")
    else:
        print("  Aucun fichier de certificats parses trouve")
        print("   Executez d'abord: python scripts/parser/parse_cert.py")

if __name__ == "__main__":
    main()