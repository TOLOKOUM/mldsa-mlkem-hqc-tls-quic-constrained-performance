#!/usr/bin/env bash
found=0
for f in $(find captures -name "resource_usage_*.csv" 2>/dev/null); do
    bad=$(awk -F, 'NR>1 && NF != 11 {c++} END{print c+0}' "$f")
    if [ "$bad" -gt 0 ]; then
        echo "SUSPECT: $f ($bad ligne(s) avec un nombre de colonnes inattendu)"
        found=1
    fi
done
if [ "$found" -eq 0 ]; then
    echo "Aucun fichier resource_usage_*.csv suspect trouvé — tous ont 11 colonnes par ligne."
fi
