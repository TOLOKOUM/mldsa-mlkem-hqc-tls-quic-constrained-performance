# Pré-enregistrement — campagne S2 « intervention sur la capacité du premier tour »

**Statut** : brouillon rédigé le 12/11/2026, à figer (commit + tag `prereg-S2` + dépôt horodaté) APRÈS la phase 0 de chaque famille et AVANT son premier bloc de mesure.
Toute modification postérieure au gel est une **déviation**, listée dans l'article. Aucun temps de la campagne S2 n'a été lu à la date de rédaction.

## 1. Question et lien avec la campagne S

La campagne S a fait varier la **taille F** du vol serveur (inégalité F > C) et a testé *où* l'escalier monte. Elle n'a **jamais fait varier la capacité C** du premier tour :
ni la fenêtre initiale TCP, ni le premier vol client (anti-amplification QUIC). Un relecteur peut donc écrire que le « mécanisme » n'est pas démontré par intervention.
La campagne S2 intervient sur C et écrit **avant les temps** où le seuil doit se déplacer. Elle ne remplace pas la campagne S ; elle en réutilise le modèle figé (`seuil_S/predict_freeze.py`,
`tools/07_threshold_model.py`, `tools/11_modele_ecritures_tls.py`) et les constantes calées en phase 0 de la campagne S (datagramme 1 220 o, `--amp-sub 28`, `--q-offset 42`).

## 2. Interventions et règles rivales

Pour chaque famille, deux règles sont comparées (colonnes `rule_a` / `rule_b` de `predictions_frozen.csv`). *k* = nombre d'allers-retours ajoutés par rapport à la chaîne de base de la famille.

| Famille | Intervention (variable manipulée) | Règle a (la capacité intervenue agit) | Règle b (l'intervention est sans effet) |
|---|---|---|---|
| TLS_IW4 | `initcwnd = 4` sur la route du réseau connecté du **serveur** (au lieu de 10) | règle « écritures (BIO) » de la campagne S avec fenêtre initiale 4 segments | même règle avec fenêtre 10 (valeur de la campagne S) |
| TLS_IW20 | `initcwnd = 20` | idem, fenêtre 20 segments | idem, fenêtre 10 |
| QUIC_C | partage de clé client plus gros : KEM `hqc128` (partage de 2 249 o) à la place de ML-KEM ; signature de base Ed25519, pont ML-DSA-44 | anti-amplification avec le B_c **mesuré en phase 0** (formule a priori : 3 datagrammes Initial de 1 220 o, soit B_c = 3 660 o, salve serveur 1 = 3·B_c − 28) | anti-amplification avec B_c = 2 440 o (valeur de la campagne S : la taille du partage client n'entre pas) |

Seuils prédits (taille de chaîne remplie en octets, premier et second paliers ; valeurs provisoires issues du brouillon de gel, recalculées au gel avec les valeurs de phase 0) :

| Famille | Règle a | Règle b |
|---|---|---|
| TLS_IW4 | 4 030 ; 15 614 | 11 477 ; 41 634 |
| TLS_IW20 | 24 790 ; 83 863 | 11 477 ; 41 634 |
| QUIC_C | 5 693 ; 29 223 | 2 164 ; 25 693 |

La règle « fenêtre seule » de QUIC (première salve = W0 = 12 200 o) est écartée dès la phase 0 de la campagne S (plafond observé de 7 292 o). Elle reste consignée dans `thresholds_frozen.csv` (seuil de chaîne 6 897 o pour QUIC_C) et
dans l'encadrement des seuils (E6) ; elle prédit *k* = 0 pour les cellules 5 950 et 6 550 o, où la règle a prédit *k* = 1.
La règle « octets » de TLS, déjà infirmée en campagne S (0/8), n'est pas rejouée.

Prédictions pour *k* = 2 (second palier) : **secondaires**, car elles reposent sur la loi de doublement de la fenêtre.
Pour QUIC_C, le second palier est hors plan (second palier QUIC mal localisé en campagne S).

## 3. Plan

Mesure : `App-ready duration` (`hs_ms` en sensibilité), sans perte, RTT ∈ {50, 150} ms (délai aller 25 / 75 ms), **20 blocs**, 10 connexions par paire et par bloc (200 par paire et par cellule), une visite par cellule et par bloc,
ordre randomisé par bloc (`run_campaign_ext.sh`), 5 connexions d'échauffement par visite, MTU 1 500, `tcp_no_metrics_save=1` vérifié par le lanceur. Taille manipulée : `CERT_PAD_TARGET_DER` (chaîne classique remplie : aucun calcul post-quantique dans le remplissage).

| Famille | Protocole | Base / pont | KEM | Cellules remplies | Cellules discriminantes primaires | Cellules non discriminantes primaires | Secondaires | Visites par bloc | Connexions (20 blocs) |
|---|---|---|---|---|---|---|---|---|---|
| TLS_IW4 | TLS 1.3 | secp384r1 / mldsa65 | x448_mlkem768 | 14 | 5 (4 300 à 11 150 o) | 7 | 2 (15 850, 20 000) | 37 | 6 700 |
| TLS_IW20 | TLS 1.3 | secp384r1 / mldsa65 | x448_mlkem768 | 14 | 5 (11 750 à 24 450 o) | 7 | 2 (41 900, 46 000) | 37 | 6 700 |
| QUIC_C | QUIC | ed25519 / mldsa44 | hqc128 | 11 | 5 (2 400 à 5 350 o) | 6 | 0 | 29 | 5 300 |

Les cellules `pcap` (RTT 50 ms, 5 flux par bloc ; 6 cellules remplies plus la base en TLS, 4 plus la base en QUIC_C) servent à la lecture mécaniste (M1) et ne participent pas à l'estimation de *k*.
Chaque taille est à ≥ 60 o (TLS) / ≥ 150 o (QUIC) de la frontière la plus proche de **chaque** règle (marges dans les colonnes `margin_a`, `margin_b` de `predictions_frozen.csv` ; contrôle dans `predict_freeze_S2.py`).
Durée estimée (même base que la campagne S : ≈ 50 s par visite ; **estimation d'ordre de grandeur**, à recalibrer après la phase 0) : ≈ 0,5 h (TLS_IW4), 0,5 h (TLS_IW20), 0,4 h (QUIC_C) par bloc, soit ≈ 10 h de banc par famille TLS et ≈ 8 h pour QUIC_C (sortie de `make_plan_S2.py`). Les colonnes « Connexions » comptent les cellules de mesure et les cellules pcap, échauffement exclu.

## 4. Phases

**Phase 0 (aveugle aux temps, 1 bloc par famille, 10 connexions par cellule avec pcap ; RTT 50 ms en TLS, RTT 0 en QUIC comme en campagne S)** — `plan_S2_phase0.csv`, `phase0_check.py` (celui de la campagne S) : n'affiche **aucune durée**. Critères, évalués famille par famille :

*TLS (TLS_IW4, TLS_IW20)*
- **P0-T1** réalisabilité : taux de réussite 100 % dans toutes les cellules ; sinon la taille est retirée avant gel.
- **P0-T2** intervention effective : dans les cellules de phase 0 où les deux règles prédisent un nombre de segments différent pour la première ronde (TLS_IW4 : pad 4 300, 11 750, 20 000 o, `fw_seg_a` = 4 contre `fw_seg_b` = 5, 10, 10 ; TLS_IW20 : pad 11 750, 25 050, 46 000 o, `fw_seg_a` = 11, 20, 20 contre 10, 10, 10), le nombre de segments de la première ronde serveur lu dans le pcap (`segs_first`, médiane) vaut `fw_seg_a` de `predictions_frozen.csv`. **Si ce n'est pas le cas, la famille est abandonnée avant gel** et le résultat de phase 0 est rapporté tel quel (l'intervention `initcwnd` n'est alors pas vérifiée sur ce banc ; la fenêtre de réception annoncée par le client est alors lue dans le pcap pour diagnostic).
- **P0-T3** octets reçus = vol prédit ± 10 o ; sinon `A_TLS` est recalé (journalisé).
- **P0-T4** le journal de bloc contient la ligne `initcwnd[...]=N route_avant=… route_apres=…` (vérification noyau faite par le lanceur, arrêt fatal sinon).

*QUIC (QUIC_C)*
- **P0-Q1** réalisabilité (HQC-128 en QUIC, chaînes jusqu'à 12 000 o).
- **P0-Q2** B_c : nombre et taille des datagrammes Initial client lus dans le pcap ⇒ `--bc hqc128=<octets>`. **Si B_c mesuré = 2 440 o** (identique à la campagne S), les règles a et b coïncident : QUIC_C est abandonnée avant gel et ce fait est rapporté (la taille du partage client ne modifie alors pas B_c).
- **P0-Q3** plafond de la salve serveur 1 = 3·B_c − 28 dans les cellules dont le vol le dépasse ; sinon la règle a est infirmée en phase 0 et rapportée comme telle.
- **P0-Q4** `--amp-sub` et `--q-offset` : recalés sur les cellules de phase 0 si mesurables, sinon valeurs de la campagne S (28 et 42).

Journal des calages de phase 0 (aucune durée consultée). (i) 12/11/2026, TLS_IW4, 1ʳᵉ exécution à RTT 0 : octets reçus = vol prédit à ± 0,5 o dans les 7 cellules (P0-T1 et P0-T3 satisfaits) ; en revanche le critère P0-T2 n'est **pas évaluable à RTT 0** : le détecteur de rondes de `fw_segments.py` ouvre une nouvelle ronde après un écart > 0,4 RTT, donc à RTT 0 toute la rafale (jusqu'à 16 segments à 20 000 o) apparaît comme une seule ronde. Le critère de la présente pré-inscription était mal posé (erreur de conception, découverte avant tout temps) : P0-T2 est évalué à RTT 50 ms (`make_plan_S2.py` corrigé : phase 0 TLS à RTT 50 ms). Aucune famille n'est abandonnée sur cette base ; aucune durée n'a été lue. (ii) 12/11/2026, TLS_IW4, phase 0 à RTT 50 ms (aucune durée lue) : réussite 100 % ; octets reçus = vol prédit à ± 1,5 o dans les 7 cellules ; manifeste : `initcwnd[...]=4`, route après portant `initcwnd 4` ; première ronde serveur = 4 segments (5 544 o = `fw_bytes_a`) aux cellules 4 300, 11 750 et 20 000 o, rondes observées 2, 2 et 3 (prédites par la règle a : 2, 2 et 3 ; règle b : 5, 10 et 10 segments) ; base ML-DSA-65 : 4 segments, 2 rondes. P0-T2 satisfait ; aucun calage de constante ; gel sans argument supplémentaire. (iii) autres familles à compléter : _____.

**Gel** : `predict_freeze_S2.py` (un dossier par famille) ⇒ `predictions_frozen.csv`, `thresholds_frozen.csv`, `constants_frozen.json`, `SHA256SUMS_frozen.txt` ; plans par `make_plan_S2.py` ; sha256 de `predict_freeze_S2.py`, `make_plan_S2.py`, `analyse_S2.py`, du patch `launcher_initcwnd.patch`, de `Launcher_ext.sh` patché et de ce fichier. Commit + tag `prereg-S2` + push (horodatage GitHub, **sans `--force`**) ; dépôt OSF Registries ou Zenodo recommandé (horodatage tiers).
**Mesure** : 20 blocs par famille. Pendant la mesure, seuls les contrôles sans durée (complétude, échecs, octets reçus, journal `initcwnd`) sont consultés.
**Analyse** : `analyse_S2.py` (refuse de tourner si les empreintes gelées ne correspondent plus), puis `fw_segments.py` pour M1.

## 5. Estimateurs (figés avant les données)

Identiques à la campagne S. `D_b(X, RTT) = médiane_b(app_ms | X) − médiane_b(app_ms | base)` (même famille, même signature, même bloc, même RTT) ; `k_b(X) = [D_b(X,150) − D_b(X,50)] / 100` ;
`k(X)` = moyenne des `k_b` sur les 20 blocs ; IC 95 % : bootstrap percentile, 10 000 rééchantillonnages conjoints des 20 blocs (graine 20261113). **L'estimateur primaire est la médiane par bloc ; la moyenne par bloc est une sensibilité.**
La pente entre deux RTT élimine `D(0)` et la constante de recouvrement `T` à condition que `T < 50 ms` ; pour HQC-128 (QUIC_C) le calcul n'a pas été mesuré dans cette configuration ; les micro-benchmarks isolés disponibles
(`microbench_results`, 2 août 2026) donnent 3,18 / 5,97 / 9,72 ms (génération / encapsulation / décapsulation) : le calcul côté serveur reste très inférieur à 50 ms (hypothèse, vérifiée a posteriori par C1).
Verdict par cellule et par règle *r* : **PASS** si l'IC ⊂ [k_r − 0,25 ; k_r + 0,25] ; **FAIL** si l'IC est hors de cette bande ; **INCONCLUSIF** sinon.

## 6. Points d'arrêt et règles de décision

**Primaires (confirmatoires), par famille**
- **E3 — garde** (TLS_IW4 : 7 cellules ; TLS_IW20 : 7 ; QUIC_C : 6). Cellules primaires non discriminantes (les deux règles s'accordent) : fraction avec |k − k_prédit| ≤ 0,25 ≥ 0,90 ; sinon E1/E2 sont **non interprétables**.
- **E1 — TLS** (TLS_IW4 : 5 cellules ; TLS_IW20 : 5 cellules) et **E2 — QUIC** (QUIC_C : 5 cellules) : « règle r confirmée » ⇔ fraction observée ≥ 0,80 **et** quantile 2,5 % du bootstrap conjoint ≥ 0,60. Issues : *a confirmée* / *b confirmée* / *aucune*.
- **E6 — localisation des seuils.** Encadrement [dernière taille dont l'IC est < palier − 0,5 ; première taille dont l'IC est > palier − 0,5] ; rapporté pour chaque règle prédite (dont « fenêtre seule » en QUIC_C).

**Secondaires** : E4 (cellules de *k* ≥ 2) ; E5 (monotonie : baisse > 0,10 d'une taille à la suivante) ; M1 (pcap : segments de la première ronde, rondes) ; **E8 dose–réponse (TLS)** : le premier seuil se déplace dans l'ordre
TLS_IW4 < (TLS_1500 de la campagne S, encadrement (11 300 ; 11 650] o) < TLS_IW20 ; la comparaison avec la campagne S est **descriptive** (autre jour, autre configuration de bloc).
Sensibilité : métrique `hs_ms` ; moyenne au lieu de la médiane par bloc ; exclusion des blocs à échec > 2 %.

**Contrôles** : C1 placebo (base paire contre impaire) IC de *k* ⊂ [−0,05 ; 0,05] ; C2 pont (ML-DSA, chaîne d'origine) classé contre *k_a*, *k_b* ; C3 octets reçus = vol prédit ± 10 o (TLS, ≥ 95 % des cellules) ; C4 taux d'échec ≤ 2 % par cellule.

## 7. Ce que nous écrirons dans chaque cas (engagement préalable)

| Résultat | Formulation dans l'article |
|---|---|
| TLS_IW4 et TLS_IW20 : E3 conforme, règle a confirmée, E6 dans l'encadrement | Le seuil TLS se déplace avec la fenêtre initiale TCP du serveur comme prédit (4 030 / 11 477 / 24 790 o) : le mécanisme est établi **par intervention** sur cette pile. |
| Une seule des deux familles TLS confirmée | Le déplacement est confirmé pour *iw* = … seulement ; nous ne revendiquons que cette dose. |
| TLS : règle b confirmée (seuil inchangé) | La fenêtre initiale TCP **n'est pas** ce qui fixe le seuil TLS sur cette pile ; la description du mécanisme est retirée du modèle ; les résultats de la campagne S sont relus en conséquence. |
| TLS : aucune règle confirmée | Aucune des deux règles n'explique le déplacement ; l'article présente *k* par taille de vol de façon empirique et retire toute affirmation de prédiction hors échantillon. |
| QUIC_C : règle a confirmée | Le seuil QUIC suit B_c (partage de clé client plus gros ⇒ seuil déplacé comme 3·B_c − 28) ; l'ancrage de l'anti-amplification passe de « calibré sur un B_c » à « testé par intervention ». |
| QUIC_C : règle b confirmée | B_c ne gouverne pas le seuil dans cette configuration ; l'explication par anti-amplification est retirée ou restreinte. |
| QUIC_C abandonnée en phase 0 (B_c inchangé) | Rapporté : la taille du partage client ne modifie pas B_c sur MsQuic dans cette configuration ; aucune intervention sur B_c n'a été possible. |
| Famille abandonnée en phase 0 (P0-T2) | Rapporté : l'intervention `initcwnd` n'a pas pu être vérifiée sur ce banc ; l'article reste limité à la campagne S. |
| E3 non conforme | Résultat non interprétable ; diagnostic du banc avant toute publication. |

Dans tous les cas la figure « escalier » (k observé, IC 95 %, règles a et b, par famille) est publiée telle quelle.

## 8. Règles de conduite

- Aucune ouverture des durées (`app_ms`, `hs_ms`) avant la fin du bloc 20 de la famille concernée.
- Noyau, image Docker, gouverneur CPU et `no_turbo` fixés pendant toute la campagne ; un changement ⇒ bloc marqué et analyse de sensibilité.
- Exclusions de blocs ou de cellules décidées sur critères **sans durée**, et listées.
- Données brutes (journaux + pcap + manifestes) archivées avant l'analyse.
- Une famille par exécution : un dossier de captures, un dossier d'état et un dossier de gel par famille.

## 9. Limites déclarées d'avance

Même machine, même pile (OpenSSL/oqs-provider pour TLS, MsQuic pour QUIC), même réseau émulé ; `initcwnd` n'est modifié que sur le **serveur** (la fenêtre de réception du client n'est pas manipulée) ;
la fenêtre initiale de MsQuic (`InitialWindowPackets`) n'est **pas** manipulée (non exposée par le banc actuel) ; en QUIC_C, l'intervention sur B_c change aussi le KEM (HQC-128), donc aussi l'octet du vol serveur (inclus dans la prédiction) et le calcul (non isolé) ;
le remplissage d'une chaîne classique isole les octets mais ne reproduit pas la structure d'une chaîne ML-DSA ; la campagne ne dit rien des pertes, de la reprise ni d'autres piles.

## 10. Empreintes à remplir au gel

| Fichier | sha256 |
|---|---|
| predictions_frozen.csv (une ligne par famille) | |
| thresholds_frozen.csv | |
| constants_frozen.json | |
| predict_freeze_S2.py | |
| make_plan_S2.py | |
| analyse_S2.py | |
| launcher_initcwnd.patch | |
| Launcher_ext.sh (patché) | |
| plan_S2_all.csv | |
| Commit / tag / DOI de dépôt | |
