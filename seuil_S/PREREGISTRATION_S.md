# Pré-enregistrement — campagne S « franchissement de seuil à prédictions figées »

**Statut** : brouillon rédigé le 08/11/2026, à figer (commit + tag + dépôt horodaté) APRÈS la phase 0 et AVANT le premier bloc de mesure.
Toute modification postérieure au gel est une **déviation** : elle est listée dans l'article (colonne « modifié après gel »).

## 1. Question

L'article de référence établit, sans perte et sur une seule pile (OpenSSL/oqs-provider + MsQuic, netem, 100 Mbit/s), que la pénalité d'un
vol serveur plus gros vaut un nombre entier d'allers-retours *k*. Il **n'a jamais testé la règle de franchissement elle-même sur des
tailles non encore mesurées** : sur 42 paires, seules 5 à 7 étaient informatives, et la règle « écritures TLS » a été déduite de pcap après avoir
vu les temps. La campagne S fait varier la taille de la chaîne de certificats **de façon continue**, avec **isolation du calcul post-quantique**
(chaîne ECDSA/Ed25519 remplie à une taille cible), et confronte des prédictions écrites **avant** les temps.

Idée directrice : une règle qui prédit *où* l'escalier monte, à quelques centaines d'octets près, pour **deux protocoles, deux MTU et deux KEM**, est
autrement plus forte qu'une règle ajustée après coup.

## 2. Règles rivales (figées dans `predict_freeze.py`, empreinte sha256 consignée)

Nombre d'allers-retours du vol serveur : `rounds`. Pénalité prédite : `k = rounds(chaîne remplie X) − rounds(chaîne de base)`.
Croissance de la fenêtre : capacité cumulée après *r* tours = `C1 + U·(2^r − 2)` (doublement), `U` = fenêtre initiale.

| Protocole | Règle a | Règle b |
|---|---|---|
| TLS/TCP (MSS = MTU − 52) | **octets** : segments = ⌈F / MSS⌉ ; fenêtre initiale 10 segments (`C1 = U = 10`) | **écritures (« BIO »)** : le vol part en écritures du tampon d'écriture OpenSSL (4 096 o) ; le dernier segment de chaque écriture est partiel et consomme un segment de fenêtre (mécanisme déduit des pcap v2, x448_mlkem768) |
| QUIC | **amp** : première salve = min(3·B_c, W0), W0 = 10 datagrammes ; puis doublement de W0 | **cwnd** : la limite d'anti-amplification n'agit pas : première salve = W0 |

Remarques d'honnêteté : (i) la règle « cwnd » est déjà défavorisée par la cellule pont ML-DSA-65/QUIC de la campagne v2 (k observé ≈ 1 contre 0 prédit) ; elle sert de
rival minimal et rend le test E2 sévère seulement par la **localisation** (E6) et le **rapport inter-KEM** (E7) ; (ii) les prédictions pour **k = 2** (second palier) reposent sur
l'hypothèse de doublement, plus fragile : elles sont **secondaires**.

Constantes (valeurs par défaut ; les valeurs mesurées en phase 0 les remplacent au gel) : MSS 1 448 / 1 228 ; fenêtre initiale TCP 10 segments ; tampon 4 096 o ;
`A_TLS` 267, `SH_FIX` 100 ; QUIC : datagramme `QUIC_DGRAM` (défaut 1 252), W0 = 10 × `QUIC_DGRAM`, `RHO_QUIC` 1,037 ; tailles des partages de clés dans `constants_frozen.json`.

## 3. Plan

Variable manipulée : `CERT_PAD_TARGET_DER` = taille DER de la chaîne (feuille remplie ; signature ECDSA P-384 ou Ed25519 **classique**, donc aucun calcul post-quantique).
Mesure : `App-ready duration` (`hs_ms` en sensibilité), sans perte, RTT ∈ {50, 150} ms (délai aller 25 / 75 ms), 20 blocs, 10 connexions par paire et par bloc (une visite par cellule et par bloc, sans micro-lots),
ordre des cellules et des paires randomisé par bloc (`run_campaign_ext.sh`, graine maître fixée au gel), 5 connexions d'échauffement par visite.

| Famille | Protocole | Signature (base) / pont | KEM | MTU | Cellules remplies | Rôle |
|---|---|---|---|---|---|---|
| TLS_1500 | TLS 1.3 | secp384r1 / mldsa65 | x448_mlkem768 | 1500 | 15 | 1ᵉʳ et 2ᵉ paliers TCP |
| TLS_1280 | TLS 1.3 | secp384r1 / mldsa65 | x448_mlkem768 | 1280 | 6 | « mêmes octets, k différent » (MSS 1 228) |
| QUIC_A | QUIC | secp384r1 / mldsa65 | x448_mlkem768 | 1500 | 12 | 2 datagrammes Initial client (B_c) |
| QUIC_B | QUIC | ed25519 / mldsa44 | x25519_mlkem512 | 1500 | 12 | réplication : autre KEM et autre signature (B_c identique à QUIC_A : 2 datagrammes Initial, mesuré en phase 0) |

Les tailles QUIC sont **déduites** des seuils calculés avec les constantes de la phase 0 (décalages fixes en octets : voir `auto_quic_sizes`). Chaque taille est à **≥ 60 o (TLS) / ≥ 150 o (QUIC)**
de la frontière la plus proche de **chaque** règle (assertion dans le script). Cellules discriminantes primaires (règles a et b prédisent des *k* différents, tous deux ≤ 1) : 8 en TLS, 8 en QUIC.
Cellules **pont** (signature post-quantique de même niveau, chaîne d'origine, dans le même bloc que la base) : 4.
Cellules mécanistes `__pcap` (RTT 50 ms, 5 flux par bloc) : 24, hors estimation de *k*.
Volume : 98 cellules de mesure, ≈ 21 200 connexions mesurées. Durée estimée (surcoût fixe ≈ 40 s par visite mesuré en v2 ; 122 visites par bloc avec les cellules pcap) : ≈ 1,7 h par bloc, ≈ 34 h de banc au total, soit ≈ 5 jours à ≤ 4 blocs par jour ; la phase 0 dure ≈ 20–25 min. Estimation d'ordre de grandeur, à recalibrer après la phase 0.

## 4. Phases

**Phase 0 (aveugle aux temps, 1 bloc, RTT 0)** — `plan_S_phase0.csv`, `phase0_check.py` : n'affiche **aucune durée**. Critères :
(1) toutes les tailles sont réalisables (taux de réussite 100 %, y compris TLS 46 000 o et QUIC 35 500 o) ; sinon la taille est retirée **avant** gel ;
(2) TLS : octets reçus = vol prédit ± 10 o ; sinon `A_TLS` est recalé ; (3) QUIC : taille de datagramme et B_c lus dans les pcap ⇒ `--quic-dgram`, `--bc`, `--rho-quic` de `predict_freeze.py`.
**Journal des calages de phase 0 (aucune durée consultée).** (i) 08/11/2026, 1ʳᵉ exécution (cellules TLS, RTT 0) : octets reçus = vol prédit ± 2 o dans 12 cellules sur 13 ; écart de +43,5 o à 46 000 o. Cause identifiée a priori par la norme (RFC 8446 §5.1 : un message Certificate de plus de 16 384 o est fragmenté en enregistrements, chacun ajoutant 22 o : en-tête 5, type interne 1, étiquette 16) ; le modèle (`Model.records`) fragmente désormais le message Certificate ; après correction, vol prédit à 46 000 o = 47 559 o contre 47 558,5 o observés. Les prédictions pour les chaînes > 16 349 o changent de 22 o par enregistrement supplémentaire ; les marges minimales restent ≥ 60 o (TLS). (ii) Format des captures du banc : `pcap_perconn/block<K>of<N>/<sig>_<kem>/block.pcap` + `conn_windows.csv` (capture continue, flux rattachés aux exécutions) ; `fw_segments.py` et `phase0_check.py` lisent ce format. (iii) QUIC, 08/11/2026 (captures de phase 0, RTT 0, aucune durée) : datagrammes de 1 220 o ; B_c = 2 440 o (2 datagrammes) pour **les deux** KEM (x448_mlkem768 **et** x25519_mlkem512) ; la salve serveur 1 est plafonnée à 7 292 o = 3 × B_c − 28 (6 datagrammes, dont le dernier de 1 192 o) dans les 8 cellules dont le vol dépasse ce plafond (bases ML-DSA comprises) et ne l'est pas quand le vol (4 567 o, 7 203 o) tient dans 7 292 o ; le serveur envoie ensuite 4 018 o de données après la poignée de main (identiques dans toutes les cellules). Conséquences : (a) la règle *amp* est soutenue mécaniquement **avant** toute durée ; la règle *cwnd* (W0 = 12 200 o) est écartée par ce plafond, et E2 teste désormais surtout la localisation du seuil (E6) en durée ; (b) QUIC_B ne divise plus le seuil par 2 (même B_c) : E7 devient non discriminant (voir §6) ; (c) calage : `--quic-dgram 1220`, `--bc` = 2 440 pour chaque KEM, `--amp-sub 28`, `--q-offset` = médiane (salve 1 − vol prédit) des cellules remplies non plafonnées (+42 o : médiane des cinq écarts 33, 39, 41,5, 59 et 71 o ; le surcoût QUIC est additif, non proportionnel). Arguments de gel utilisés : `--quic-dgram 1220 --bc x25519_mlkem512=2440 --bc x448_mlkem768=2440 --amp-sub 28 --q-offset 42` ; les tailles de grille QUIC sont recalculées à partir de ces constantes (marges ≥ 150 o).
**Gel** : `predict_freeze.py` avec les valeurs de phase 0 ⇒ `predictions_frozen.csv`, `thresholds_frozen.csv`, `constants_frozen.json`, `SHA256SUMS_frozen.txt` ; plans générés ;
`analyse_seuil.py`, `fw_segments.py`, ce fichier : sha256. Commit + tag `prereg-S` + push (horodatage GitHub) ; dépôt OSF Registries recommandé (horodatage tiers immuable).
**Mesure** : 20 blocs. Pendant la mesure, **seuls** les contrôles automatiques sans durée sont consultés (complétude, taux d'échec, octets reçus).
**Analyse** : `analyse_seuil.py` (refuse de tourner si les empreintes gelées ne correspondent plus) puis `fw_segments.py`.

## 5. Estimateurs

`D_b(X, RTT) = médiane_b(app_ms | X) − médiane_b(app_ms | base)` (même famille, même signature, même bloc, même RTT) ;
`k_b(X) = [D_b(X,150) − D_b(X,50)] / 100` ; `k(X)` = moyenne des `k_b` ; IC 95 % : bootstrap percentile, 10 000 rééchantillonnages **conjoints** des 20 blocs (graine 20261108).
La pente entre deux RTT élimine `D(0)` et la constante de recouvrement `T` (T < 50 ms pour ECDSA/Ed25519 : aucun calcul post-quantique à recouvrir).
Verdict par cellule et par règle *r* : **PASS** si l'IC ⊂ [k_r − 0,25 ; k_r + 0,25] ; **FAIL** si l'IC est hors de cette bande ; **INCONCLUSIF** sinon.

## 6. Points d'arrêt et règles de décision

**Primaires (confirmatoires)**
- **E3 — garde.** Cellules primaires non discriminantes (toutes les règles s'accordent) : fraction avec |k − k_prédit| ≤ 0,25 ≥ 0,90. Sinon, E1 et E2 sont déclarés **non interprétables** (le banc ne reproduit pas l'escalier de base).
- **E1 — TLS.** Sur les 8 cellules discriminantes primaires (TLS_1500 + TLS_1280) : « règle r confirmée » ⇔ fraction observée ≥ 0,80 **et** quantile 2,5 % du bootstrap conjoint ≥ 0,60. Issues : *écritures confirmée* / *octets confirmée* / *aucune*.
- **E2 — QUIC.** Idem sur les 8 cellules discriminantes primaires (QUIC_A + QUIC_B), règles *amp* / *cwnd*.
- **E6 — localisation des seuils.** Pour chaque famille et chaque palier : encadrement [dernière taille dont l'IC est < palier − 0,5 ; première taille dont l'IC est > palier − 0,5]. Le seuil prédit par une règle est « dans l'encadrement » ou non (rapporté pour les deux règles).
- **E7 — réplication inter-KEM (QUIC).** B_c est identique pour les deux KEM (2 datagrammes de 1 220 o, mesuré en phase 0) : les deux règles prédisent donc un rapport de seuils (octets de vol) QUIC_A / QUIC_B ≈ 1 ; E7 **ne discrimine plus** entre règles et ne sert qu'à vérifier que le seuil en octets de vol ne dépend pas du KEM. Les règles *amp* (≈ 3 × B_c − 28 = 7 292 o) et *cwnd* (W0 = 12 200 o) divergent sur la **valeur absolue** du seuil, testée par E6.

**Secondaires**
- **E4** : cellules à palier *k* ≥ 2 (5 discriminantes) ; **E5** : monotonie (baisse > 0,10 d'une taille à la suivante : comptage) ; **M1** (pcap, `fw_segments.py`) : en TLS, octets de la première ronde et nombre de rondes
  contre les deux règles ; en QUIC, présence d'une seconde salve après la réponse du client.
- Sensibilité : métrique `hs_ms` ; moyenne au lieu de la médiane par bloc ; exclusion des blocs à échec > 2 %.

**Contrôles**
- C1 placebo (base paire contre impaire) : IC de *k* ⊂ [−0,05 ; 0,05] ; C2 pont (ML-DSA sans remplissage) : classement contre *k_a*, *k_b* ; C3 taille : TLS octets reçus = vol prédit ± 10 o dans ≥ 95 % des cellules, QUIC ± 3 % ; C4 taux d'échec ≤ 2 % par cellule.

## 7. Ce que nous écrirons dans chaque cas (engagement préalable)

| Résultat | Formulation dans l'article |
|---|---|
| E3 conforme, E1 « écritures », E6 dans l'encadrement | La règle d'écritures TLS, formulée avant les temps, prédit la position du seuil à moins de la largeur de l'encadrement ; la règle « octets » est écartée dans la fenêtre [11,5 ; 13,0] ko. |
| E1 « octets » | La règle déduite des pcap v2 est **infirmée** ; le seuil TLS suit la règle en octets. Les résultats v2 sont relus en conséquence ; la description du tampon d'écriture est retirée du modèle. |
| E1 « aucune » | Aucune des deux règles n'explique le seuil TLS sur cette pile ; l'article présente k par taille de vol de façon empirique et supprime toute affirmation de prédiction pour TLS hors échantillon. |
| E2/E7 conformes | L'anti-amplification × B_c est confirmée quantitativement (déplacement du seuil proportionnel à B_c entre deux KEM). |
| E4 échoue (paliers k ≥ 2) | Le doublement de la fenêtre n'est pas établi au-delà du premier palier ; seul le premier palier est revendiqué. |
| E3 non conforme | Résultat non interprétable ; diagnostic du banc avant toute publication. |

Dans tous les cas, la figure « escalier » (k observé et IC 95 % contre les deux règles, par famille) est publiée telle quelle.

## 8. Règles de conduite

- Aucune ouverture des durées (`app_ms`, `hs_ms`) avant la fin du bloc 20 ; seuls les contrôles de complétude, d'échec et d'octets reçus sont autorisés.
- Noyau, image Docker, gouverneur CPU et `no_turbo` fixés pendant toute la campagne (aucune mise à jour système) ; un changement ⇒ bloc marqué et analyse de sensibilité.
- `tcp_no_metrics_save=1` vérifié par le Launcher (arrêt fatal sinon). Valeur de `initcwnd` / `net.ipv4.tcp_*` consignée dans le journal de chaque bloc.
- Toute exclusion de bloc ou de cellule est décidée sur critères **sans durée** (échec, température, gouverneur) et listée.
- Les données brutes (journaux + pcap) sont archivées (Zenodo, nouvelle version) **avant** l'analyse.

## 9. Limites déclarées d'avance

Pile unique ; réseau émulé (netem, 100 Mbit/s, sans perte) ; remplissage d'une chaîne classique **isole les octets**, il ne reproduit pas le calcul ni la structure des certificats ML-DSA ;
fenêtre initiale TCP supposée égale à 10 segments (vérifiée par pcap, non lue dans le noyau) ; état interne de MsQuic non lu (observations par pcap) ; second palier (*k* = 2) reposant sur le doublement de la fenêtre ;
la règle d'écritures est déduite d'un seul KEM (x448_mlkem768) et d'un seul serveur (`s_server` d'OpenSSL) ; la campagne ne dit rien des pertes, de la reprise ni de HQC.

## 10. Empreintes à remplir au gel

| Fichier | sha256 |
|---|---|
| predictions_frozen.csv | |
| thresholds_frozen.csv | |
| constants_frozen.json | |
| predict_freeze.py | |
| analyse_seuil.py | |
| fw_segments.py | |
| plan_S_all.csv | |
| Commit / tag / DOI de dépôt | |
