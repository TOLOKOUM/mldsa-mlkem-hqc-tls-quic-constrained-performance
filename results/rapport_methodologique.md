# Annexe méthodologique — Calibration réseau à partir de mesures terrain

**Nombre de sessions valides analysées : 12**

> ⚠️ Moins de 18 sessions collectées (minimum recommandé pour couvrir 3 opérateurs × 2 créneaux × 3 jours). Les scénarios dérivés ci-dessous restent calculables mais leur représentativité statistique est plus faible — à mentionner explicitement dans les limites de l'étude si le nombre de sessions reste bas.


Opérateurs/connexions couverts : MTN, Orange

Créneaux couverts : creuse, pointe


## Scénarios réseau dérivés (remplacent les scénarios uniform-loss précédents)

| Scénario | N sessions poolées | RTT moyen (ms) | RTT p95 (ms) | Perte (%) | Gigue (ms, n sessions) | Délai tc/interface (ms) |
|---|---|---|---|---|---|---|
| Idéal (Baseline) | N/A | 0.0 | 0.0 | 0.0 | N/A | 0.0 |
| Modéré (terrain) | 5 | 125.02 | 271.0 | 1.3 | 9.268 (n=3) | 62.51 |
| Dégradé (terrain) | 6 | 167.048 | 251.0 | 1.5833 | 7.757 (n=3) | 83.52 |

## Traçabilité par scénario (agrégation, pas sélection d'une session unique)

Chaque scénario Modéré/Dégradé est désormais une **moyenne pondérée sur toutes les sessions valides** de l'opérateur correspondant (MTN→Modéré, Orange→Dégradé, mapping fixé par le design de l'étude), avec exclusion IQR des sessions aberrantes au sein du groupe. Le détail :

- **Modéré (terrain)** (MTN) : 5 session(s) utilisée(s), 1 exclue(s) par IQR, jours couverts = jeudi,samedi,vendredi, gigue disponible sur 3/5 session(s).
- **Dégradé (terrain)** (Orange) : 6 session(s) utilisée(s), 0 exclue(s) par IQR, jours couverts = jeudi,samedi,vendredi, gigue disponible sur 3/6 session(s).

## Commandes tc/netem correspondantes

Rappel méthodologique : le délai est appliqué en bidirectionnel sur eth0 des conteneurs client ET serveur, doublant le RTT déclaré. Les valeurs ci-dessous utilisent donc `delay = RTT_mesuré / 2` par interface.

- **Idéal (Baseline)** : `none (pas de restriction tc)`
- **Modéré (terrain)** : `tc qdisc add dev eth0 root netem delay 62.51ms 9.268ms loss 1.3%`
- **Dégradé (terrain)** : `tc qdisc add dev eth0 root netem delay 83.52ms 7.757ms loss 1.5833%`

## Note sur le modèle Gilbert-Elliott

Les paramètres du modèle Gilbert-Elliott (p, r, taux de perte par état) ne sont **pas modifiés** par cette recalibration terrain : ils restent ceux validés lors de la phase précédente du projet (single-cell rerun N=500 confirmant l'anomalie GE-Unstable, exclusion permanente déjà justifiée).