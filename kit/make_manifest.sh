#!/usr/bin/env bash
# make_manifest.sh -- SHA256SUMS de l'arbre du depot, hors .git (revue du 15/11/2026, point 6). A lancer a la racine du depot AVANT de tagger.
# Usage : ./make_manifest.sh > SHA256SUMS   puis : git add SHA256SUMS && git commit && git tag <tag>
find . -type f -not -path './.git/*' -not -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum
