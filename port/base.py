import os, glob, sys
import pandas as pd, numpy as np
# Dossier des donnees : variable d'environnement DATA_DIR, sinon le dossier courant.
DATA_DIR = os.environ.get("DATA_DIR", os.getcwd())
OUT_DIR = os.environ.get("OUT_DIR", os.getcwd())
def find(suffix):
    hits = sorted(glob.glob(os.path.join(DATA_DIR, "**", "*" + suffix), recursive=True))
    if not hits:
        sys.exit(f"Fichier introuvable : *{suffix} dans {DATA_DIR} (definir DATA_DIR)")
    return hits[0]
def load(name="conn.csv.gz"):
    return pd.read_csv(find(name), low_memory=False)
def load_p6():
    return pd.read_csv(find("p6_connexions.csv.gz"), low_memory=False)
