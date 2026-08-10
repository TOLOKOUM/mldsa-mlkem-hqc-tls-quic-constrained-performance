#!/usr/bin/env python3
"""
patch_launcher_idempotent.py — Rend Launcher_pq_mldsa_mlkem_hqc.sh idempotent :
avant chaque combinaison SIG_ALG/KEM, vérifie si elle est déjà présente dans
le resource_usage_*.csv du scénario en cours, et la saute si oui.

Effet : après un plantage (pumba/réseau), tu relances EXACTEMENT LA MÊME
commande qu'au départ (aucune édition manuelle du script), et il ne refait
que ce qui manque.

USAGE (une seule fois) :
    python3 patch_launcher_idempotent.py Launcher_pq_mldsa_mlkem_hqc.sh
"""
import sys
from pathlib import Path

FUNCTION_BLOCK = '''
# ── Reprise idempotente ──────────────────────────────────────────────────
# Vérifie si (sig_alg, kem) a déjà une ligne "client" dans le CSV de ce
# scénario -- basé sur les colonnes exactes (pas de correspondance de
# sous-chaîne, pour ne pas confondre "x25519" et "x25519_mlkem512").
already_done() {
    local sig="$1" kem="$2"
    [[ -f "$RESOURCE_CSV" ]] || return 1
    awk -F',' -v s="$sig" -v k="$kem" -v np="$NETWORK_PROFILE" \\
        '$4==s && $5==k && $6==np && $7=="client" {found=1} END{exit !found}' \\
        "$RESOURCE_CSV"
}

'''

SKIP_CHECK = '''        if already_done "$SIG_ALG" "$KEM"; then
            echo "     (deja present dans $RESOURCE_CSV pour ce scenario -- ignore, reprise automatique)"
            continue
        fi

'''

ANCHOR_FUNC_BEFORE = 'SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"'
ANCHOR_SKIP_AFTER = '        echo "  -> KEM: $KEM"\n'


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    path = Path(sys.argv[1])
    text = path.read_text()

    if "already_done()" in text:
        print("Le launcher semble déjà patché (fonction already_done() présente). Rien à faire.")
        return

    if ANCHOR_FUNC_BEFORE not in text:
        print(f"ERREUR : ancre d'insertion de la fonction introuvable dans {path}. "
              f"Le fichier a peut-être été modifié depuis -- patch manuel nécessaire.")
        sys.exit(1)
    if ANCHOR_SKIP_AFTER not in text:
        print(f"ERREUR : ancre d'insertion du skip-check introuvable dans {path}. "
              f"Patch manuel nécessaire.")
        sys.exit(1)

    backup = path.with_suffix(path.suffix + ".pre_idempotent.bak")
    backup.write_text(text)
    print(f"Sauvegarde de l'original : {backup}")

    text = text.replace(ANCHOR_FUNC_BEFORE, FUNCTION_BLOCK + ANCHOR_FUNC_BEFORE, 1)
    text = text.replace(ANCHOR_SKIP_AFTER, ANCHOR_SKIP_AFTER + SKIP_CHECK, 1)

    path.write_text(text)
    print(f"{path} patché avec succès.")
    print("Vérifie avec : bash -n " + str(path) + "  (test de syntaxe sans exécuter)")


if __name__ == "__main__":
    main()
