# Plan d'analyse pré-spécifié (TDSC-2026-09-3862, trajectoire A)

Version 1, rédigée le 08/10/2026, AVANT le premier bloc de la campagne principale.
Toute modification ultérieure est consignée dans `DEVIATIONS.md` (datée, motivée) ; ce fichier n'est jamais réécrit après le tag `prereg-2026-10`.

## 1. Design figé

- Plan : `plans/plan_all.csv` (137 cellules ; empreinte SHA-256 dans `PREREG_HASHES.txt`).
- 20 blocs ; graine maîtresse **20261009** ; ordre des cellules et des paires tiré indépendamment à chaque bloc (graines dérivées, journalisées dans `campaign_state/`).
- 3 visites sentinelles par bloc (pre/mid/post), paire de référence ECDSA P-384 et ML-DSA-65 avec x448_mlkem768, TLS et QUIC.
- Facteurs fixes : débit 100 Mbit/s, file netem 1000, gigue nulle, MTU 1500 sauf plan mécanistique, perte serveur→client sauf plan direction, no_turbo=1, governor performance, CPU épinglé, offloads coupés, secteur.
- COOLDOWN_TEMP_C = 59 °C ; image Docker `uma-tls-quic-pq-34` = f509a6418ff8 ; SIZE_TARGET_DER = 8700.
- Les données du pilote et du smoke test ne servent jamais à l'inférence.

## 2. Unité d'inférence et métrique

- Unité d'inférence = le **bloc**, jamais la connexion.
- Métrique primaire commune TLS/QUIC : `App-ready duration` (départ du client → première réponse applicative authentifiée). Les durées natives (Handshake duration, HandshakeFlightEnd, HANDSHAKE_DONE) sont secondaires et diagnostiques.
- Résumé par (cellule, paire, bloc) : médiane de l'App-ready des connexions réussies, taux de succès, nombre d'échecs/timeouts. Les échecs ne sont jamais imputés ; ils sont rapportés séparément.

## 3. Estimand primaire

Pour chaque protocole, KEM et condition réseau :
Δ_bloc = médiane(ML-DSA-65) − médiane(ECDSA P-384), à KEM fixé, dans le même bloc.
Estimateur : moyenne des Δ_bloc sur les 20 blocs. Incertitude : bootstrap par blocs (10 000 rééchantillons, IC 95 %). Test : sign-flip exact sur les 20 différences appariées (2^20 retournements, p minimal ≈ 1,9·10^-6). Les tests au niveau connexion sont interdits.

## 4. Hypothèses confirmatoires (écrites avant les données)

- **H1 (RQ1)** : sur le réseau idéal et à RTT 0, Δ ≠ 0 pour ML-DSA-65 vs ECDSA P-384 (bilatéral).
- **H2 (RQ2, taille)** : à RTT 50 ms, MTU 1500, perte 0–5 %, l'ECDSA gonflé à la taille de ML-DSA-65 reproduit l'essentiel de la pénalité. Fraction F = Δ(ECDSA gonflé) / Δ(ML-DSA-65), avec IC par blocs. Règle de décision : « la taille domine » si la borne basse de l'IC de F > 0,5 ; « le calcul domine » si la borne haute < 0,5 ; sinon « non concluant ».
- **H3 (RQ2, MTU)** : Δ(MTU 1280) > Δ(MTU 1500) sous perte > 0, TLS et QUIC (unilatéral).
- **H4 (RQ3, corrélation)** : à perte marginale égale, Δ sous GE-mild ou GE-severe ≠ Δ sous iid (bilatéral).
- **H5 (RQ3, délai)** : à perte fixée, Δ croît avec le RTT (pente de régression > 0).
- **H6 (RQ4, chaîne)** : Δ avec chaîne réaliste (CHAIN_DEPTH=2) > Δ avec chaîne minimale à RTT 50 ms, perte ≥ 1 % (unilatéral).

Multiplicité : correction de Holm sur la famille H1–H6. Tout le reste (inversions repérées après coup, croisements, plan direction, plan main) est **exploratoire** et étiqueté comme tel.

## 5. Modèle mixte et sensibilité

- Modèle sur les médianes de bloc : log(App-ready) ~ signature × condition + (1 | bloc) + (1 | jour).
- Sensibilité : (a) sans les blocs signalés par les sentinelles ; (b) moyenne tronquée au lieu de la médiane ; (c) bootstrap par jour.

## 6. Dérive et exclusions

- Bloc signalé si, pour les sentinelles, |médiane post − médiane pre| > 10 % de la médiane pre. Il reste dans l'analyse primaire et sort dans la sensibilité (a).
- Exclusions automatiques : visites de code 98 (veille), visites en échec non reprises. Aucune exclusion discrétionnaire.

## 7. Différence minimale d'intérêt

DMI = max(5 % de la médiane ECDSA de la cellule, 2 ms). Les effets sont rapportés avec leur position par rapport à la DMI. (Valeur à confirmer par l'auteur avant le tag.)

## 8. Limites déclarées d'avance

- M=2 absent de `plan_main` (25 connexions consécutives) ; warm-up de 5 par tour égal au nombre de mesures des cellules ciblées.
- Requête applicative de 31 octets (TLS) contre 100 octets (QUIC) ; TLS inclut le connect TCP (≈ 1 RTT) ; pas de QUIC mutual.
- Perte effective TLS ≈ 20 % sous le nominal (cause inconnue), mesurée par cellule et rapportée.
- Sans MTU synchronisé, la pile QUIC démarre à 1280 et sonde après le handshake ; les bras QUIC avec `QUIC_MTU_SYNC` et sans ne sont pas comparables entre eux.
- Une seule machine physique, un seul CPU x86-64, une seule pile QUIC (MsQuic) ; pas de qlog interne (PTO, cwnd) ; ARM64 et deux machines distinctes : réplication ultérieure.
- Pas de reprise de session, pas de transfert applicatif, pas de concurrence.
