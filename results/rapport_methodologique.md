# Annexe méthodologique — Calibration réseau à partir de mesures terrain

**Nombre de sessions valides analysées : 4**

> ⚠️ Moins de 18 sessions collectées (minimum recommandé pour couvrir 3 opérateurs × 2 créneaux × 3 jours). Les scénarios dérivés ci-dessous restent calculables mais leur représentativité statistique est plus faible — à mentionner explicitement dans les limites de l'étude si le nombre de sessions reste bas.


> ⚠️ Toutes les sessions proviennent du même jour et/ou du même créneau horaire. Modéré et Dégradé reflètent donc une variabilité inter-opérateurs à un instant donné, pas une variabilité temporelle (heures creuses/pointe, jours différents). À signaler explicitement en limite de l'étude tant que des sessions complémentaires (autres jours, heures creuses) n'ont pas été ajoutées.


Opérateurs/connexions couverts : MTN, Orange

Créneaux couverts : creuse, pointe


## Scénarios réseau dérivés (remplacent les scénarios uniform-loss précédents)

| Scénario | Session source | Opérateur | RTT moyen (ms) | RTT p95 (ms) | Perte (%) | Gigue (ms) | Délai tc/interface (ms) |
|---|---|---|---|---|---|---|---|
| Idéal (Baseline) | N/A (Theoretical Control) | None | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| Modéré (terrain) | 20260801_221721_MTN_4G | MTN | 60.036 | 58.835 | 0.3 | N/A | 30.02 |
| Dégradé (terrain) | 20260801_221256_Orange_4G | Orange | 130.295 | 147.0 | 0.2 | N/A | 65.15 |

## Commandes tc/netem correspondantes

Rappel méthodologique : le délai est appliqué en bidirectionnel sur eth0 des conteneurs client ET serveur, doublant le RTT déclaré. Les valeurs ci-dessous utilisent donc `delay = RTT_mesuré / 2` par interface.

- **Idéal (Baseline)** : `none (pas de restriction tc)`
- **Modéré (terrain)** : `tc qdisc add dev eth0 root netem delay 30.02ms loss 0.3%`
- **Dégradé (terrain)** : `tc qdisc add dev eth0 root netem delay 65.15ms loss 0.2%`

## Note sur le modèle Gilbert-Elliott

Les paramètres du modèle Gilbert-Elliott (p, r, taux de perte par état) ne sont **pas modifiés** par cette recalibration terrain : ils restent ceux validés lors de la phase précédente du projet (single-cell rerun N=500 confirmant l'anomalie GE-Unstable, exclusion permanente déjà justifiée).