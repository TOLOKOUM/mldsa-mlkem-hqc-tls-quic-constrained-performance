#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""make_prereg_S3.py -- ecrit PREREGISTRATION_S3.md a partir des dossiers de gel des deux bras (valeurs lues, jamais saisies a la main).
Usage : python3 seuil_S3/make_prereg_S3.py --pred1 seuil_S3/freeze_S3_PAD1 --pred0 seuil_S3/freeze_S3_PAD0 --out seuil_S3/PREREGISTRATION_S3.md --date 18/11/2026"""
import argparse, csv, json, os


def rd(p):
    return list(csv.DictReader(open(p, encoding="utf-8")))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pred1", required=True); ap.add_argument("--pred0", required=True)
    ap.add_argument("--out", default="PREREGISTRATION_S3.md"); ap.add_argument("--date", default="")
    a = ap.parse_args()
    P1 = [r for r in rd(os.path.join(a.pred1, "predictions_frozen.csv"))]
    P0 = {(r["kind"], r["chain_target"]): r for r in rd(os.path.join(a.pred0, "predictions_frozen.csv"))}
    TH = {(r["rule"], r["step"]): r for r in rd(os.path.join(a.pred1, "thresholds_frozen.csv"))}
    TH0 = {(r["rule"], r["step"]): r for r in rd(os.path.join(a.pred0, "thresholds_frozen.csv"))}
    C = json.load(open(os.path.join(a.pred1, "constants_frozen.json")))
    ov = C["phase0_overrides"]
    pad = [r for r in P1 if r["kind"] == "pad"]
    disc = [r["chain_target"] for r in pad if r["disc"] == "1" and r["tier"] == "primary"]
    nondisc = [r["chain_target"] for r in pad if r["disc"] == "0" and r["tier"] == "primary"]
    pcap = [r["chain_target"] for r in pad if r["pcap_cell"] == "1"]
    t_amp, t_bc, t_w = (int(TH[(k, "1")]["chain_threshold"]) for k in ("amp", "amp_bc", "cwnd"))
    f_amp, f_bc, f_w = (TH[(k, "1")]["flight_threshold"] for k in ("amp", "amp_bc", "cwnd"))
    s1 = [r["chain_target"] for r in pad if t_amp <= int(r["chain_target"]) < t_w]
    exp_nonzero = [r["chain_target"] for r in pad if r["disc"] == "1" and r["tier"] == "primary"]   # delta attendu = k_a(T) - k_a(C) = -1
    rows = []
    for r in pad:
        c = P0[("pad", r["chain_target"])]
        rows.append("| %s | %s | %s | %s | %s | %s | %s |" % (r["chain_target"], r["flight_a"], r["k_a"], c["k_a"], r["k_b"],
                    "oui" if r["disc"] == "1" else "non", "oui" if r["pcap_cell"] == "1" else ""))
    br1 = [r for r in P1 if r["kind"] == "bridge"][0]; br0 = P0[("bridge", "0")]
    md = f"""# Pré-enregistrement — campagne S3 « intervention sur B_c seul, à vol serveur constant »

**Statut** : rédigé le {a.date or "__/__/2026"}, à figer (commit + tag `prereg-S3` + dépôt horodaté) APRÈS la phase 0 et AVANT le premier bloc de mesure. Toute modification postérieure au gel est une **déviation**, listée dans l'article.
Aucune durée (`app_ms`, `hs_ms`) de la campagne S3 n'a été lue à la date de rédaction.

## 1. Question

Dans la campagne S2 (QUIC_C), B_c et le vol serveur variaient ensemble (le KEM changeait). La campagne S3 isole B_c : **le vol serveur reste identique** (même KEM X448+ML-KEM-768, même signature secp384r1 à chaîne remplie), et seul le premier vol du client grossit.
Hypothèse testée : le plafond d'octets que le serveur peut envoyer avant validation de l'adresse suit 3·B_c − {ov["amp_sub"]} (octets « chargés », paquets ack-eliciting du serveur).

## 2. Intervention et règles rivales

- **Intervention** : extension privée de ClientHello `0xFFB3` (remplissage de {1450} o, variable `CH_PAD_BYTES`), ajoutée par un correctif du client MsQuic (`ctx_v3/patches/apply_quic_chpad.sh`). Deux images ne différant que par cette variable d'environnement : **témoin** `uma-tls-quic-pq-34-v3c` (CH_PAD_BYTES vide : B_c = 2 440 o, 2 datagrammes), **traitement** `uma-tls-quic-pq-34-v3c-pad1450` (B_c = 3 660 o, 3 datagrammes). Le lanceur ne transmet pas la variable : un bras se distingue uniquement par l'image.
- **Règle a (B_c agit)** : première salve serveur ≤ 3·B_c − {ov["amp_sub"]} ; traitement 10 952 o, témoin 7 292 o.
- **Règle b (B_c sans effet)** : plafond 7 292 o dans les deux bras.
- **Règle « fenêtre seule »** (rivale pour les cellules secondaires) : première salve = W0 = {C["QUIC_W0"]} o.

Seuils prédits (taille de chaîne remplie, octets DER ; calage de phase 0 : datagramme {ov["quic_dgram"]} o, `--amp-sub {ov["amp_sub"]}`, `--q-offset {int(ov["q_offset"])}`) :

| Règle | Seuil 1 (chaîne) | Vol correspondant |
|---|---|---|
| a, traitement (B_c = 3 660) | {t_amp} | {f_amp} |
| b (B_c sans effet) = a, témoin (B_c = 2 440) | {t_bc} | {f_bc} |
| fenêtre seule | {t_w} | {f_w} |

Le seuil 2 (≈ 29 000 à 33 700 o) est hors plan.

## 3. Plan

Mesure : `App-ready duration` (`hs_ms` en sensibilité), sans perte, RTT ∈ {{50, 150}} ms (délai aller 25 / 75 ms), **20 blocs par bras**, 10 connexions par paire et par bloc (200 par paire et par cellule), une visite par cellule et par bloc, ordre randomisé par bloc, 5 connexions d'échauffement par visite, MTU 1 500, sans pertes.
Les deux bras ont **le même plan** (mêmes cellules, mêmes tailles, mêmes cellules pcap ; seul l'identifiant de cellule porte le nom de la famille). 29 visites par bloc (24 mesure + 5 pcap), 5 200 connexions mesurées par bras.
Les blocs des deux bras sont **entrelacés** : bloc K du traitement, bloc K du témoin, avec l'ordre inversé un bloc sur deux. Une graine, un dossier de captures et un dossier d'état par bras.

| Chaîne remplie (o) | Vol a priori (o) | k règle a, traitement | k règle a = b, témoin | k règle b, traitement | Discriminante | pcap |
|---|---|---|---|---|---|---|
""" + "\n".join(rows) + f"""

Pont ML-DSA-65 (chaîne d'origine, vol {br1["flight_a"]} o) : k attendu {br1["k_a"]} (a, traitement) contre {br1["k_b"]} (b) ; témoin : {br0["k_a"]}.
Cellules discriminantes primaires (a ≠ b, traitement) : {", ".join(disc)}. Cellules non discriminantes primaires : {", ".join(nondisc)}. Cellules secondaires « contre fenêtre seule » (S1) : {", ".join(s1)}.
Chaque taille est à ≥ 150 o de la frontière la plus proche de chaque règle, dans chaque bras (colonnes `margin_a`, `margin_b` de `predictions_frozen.csv`).

## 4. Phase 0 (aveugle aux temps)

Une exécution d'un bloc par bras, 10 connexions par cellule, avec pcap par connexion à RTT 50 ms ; aucun temps n'a été lu. Résultats : décodage 70/70 dans chaque bras ; B_c = 2 440 o (70/70, témoin) et 3 660 o (70/70, traitement), aucun cas à 4 880 o ;
plafonds observés 7 292 o (témoin) et 10 952 o (traitement), soit exactement 3·B_c − {ov["amp_sub"]} ; octets chargés du serveur identiques entre bras dans les cellules non plafonnées (écarts de médiane ≤ 5 o) ; calage `--q-offset {int(ov["q_offset"])}` (dispersion 21 o) ; 0 échec.
La capture est prise côté client, avec les datagrammes du client estampillés après le délai émulé ; l'audit utilise un RTT fixé à 25,7 ms (l'estimation automatique du RTT est surestimée d'environ 3 ms pour les flux à ClientHello en 2 datagrammes ; cet écart a d'abord produit un artefact d'audit, corrigé avant gel).

**Facteur concomitant déclaré** : dans les flux à ClientHello en 3 datagrammes (traitement), le serveur envoie en plus un datagramme de 1 260 o (non chargé : acquittement sans contenu ack-eliciting), environ 3,7 ms avant le premier datagramme du vol serveur chargé dans la capture ; il n'existe pas dans les flux à 2 datagrammes (témoin). Le contraste entre bras mesure donc l'effet conjoint de B_c et de ce datagramme ; nous ne pouvons pas les séparer.
La phrase « chaque connexion commence par un datagramme non chargé de 1 260 o » n'est vraie que pour les flux à 3 datagrammes.

## 5. Estimateurs (figés avant les données)

Identiques à S2 (`analyse_S2.py`) : `D_b(X, RTT) = médiane_b(app_ms | X) − médiane_b(app_ms | base)` (même bras, même signature, même bloc, même RTT) ; `k_b(X) = [D_b(X,150) − D_b(X,50)] / 100` ; `k(X)` = moyenne des `k_b` ; IC 95 % bootstrap par blocs (10 000 rééchantillonnages, graine 20261113). L'estimateur primaire est la médiane par bloc.
**Contraste** (`analyse_S3_contrast.py`) : `Δ(X) = k(X, traitement) − k(X, témoin)` ; erreur-type de chaque bras tirée de la largeur de son IC (largeur / 3,92), bras indépendants (blocs entrelacés mais runs distincts) : `se(Δ) = sqrt(se_T² + se_C²)` ; IC 95 % de Δ = Δ ± 1,96·se(Δ). Attendu : `Δ_att(X) = k_a(X, traitement) − k_a(X, témoin)`.
Une cellule est **conforme** si l'IC 95 % de Δ est entièrement dans [Δ_att − 0,25 ; Δ_att + 0,25]. Hypothèse déclarée : la pente entre deux RTT élimine D(0) et la constante de recouvrement T à condition que T < 50 ms (le calcul ML-KEM-768 est identique dans les deux bras).

## 6. Points d'arrêt et règles de décision

**Primaires (confirmatoires)**
- **P3 — contraste** : sur les {len(exp_nonzero)} cellules discriminantes primaires ({", ".join(exp_nonzero)} o ; Δ_att = −1) : fraction conforme ≥ 0,80 ⇒ « B_c agit dans le sens prédit » ; sinon « non confirmé ».
- **E2 — dans le bras traitement** (`analyse_S2.py`, règle FIGÉE de S2) : règle a (plafond 3·B_c − {ov["amp_sub"]} avec B_c = 3 660) confirmée si fraction ≥ 0,80 **et** quantile 2,5 % du bootstrap ≥ 0,60 ; règle b confirmée symétriquement.
- **E3 — garde, par bras** : cellules primaires non discriminantes (traitement : {len(nondisc)} ; témoin : toutes les {len(pad)}, car a = b) : fraction conforme ≥ 0,90. **Si la garde d'un bras échoue, P3 et E2 sont non interprétables.**
- **E6 — localisation** : encadrement du premier seuil dans chaque bras, comparé à {t_amp} (traitement) et {t_bc} (témoin) ; décalage observé entre bras rapporté (attendu ≈ 3 529 o de chaîne = 3 660 / 1,037).

**Secondaires** : P3c (cellules à Δ_att = 0 : fraction conforme, rapportée) ; **S1** (cellules {", ".join(s1)} o, entre {t_amp} et {t_w} : IC 95 % de k dans [0,75 ; 1,25] dans le traitement ; la fenêtre seule prédit 0) ; pont ML-DSA-65 ; E4–E5 comme S2 ; M1 (pcap : B_c, plafond, premier vol).
Sensibilité : métrique `hs_ms` ; moyenne au lieu de la médiane par bloc ; exclusion des blocs à taux d'échec > 2 %.
Contrôles : C1 placebo (base paire contre impaire) IC de k ⊂ [−0,05 ; 0,05] ; C2 pont ; C4 taux d'échec ≤ 2 % par cellule ; audit pcap par bras : B_c 2 440 / 3 660 dans 100 % des flux décodés, plafonds 7 292 / 10 952.

## 7. Ce que nous écrirons dans chaque cas (engagement préalable)

| Résultat | Formulation dans l'article |
|---|---|
| E3 conforme dans les deux bras, P3 confirmé, E2 « a » | Agrandir seul le premier vol du client (B_c : 2 440 → 3 660 o), à vol serveur identique, déplace le seuil comme 3·B_c − 28 le prédit (≈ 3,5 kB de chaîne). L'ancrage de l'anti-amplification passe de calibré à testé par intervention, avec la réserve du datagramme d'acquittement concomitant (§4). |
| P3 non confirmé, E2 « b » | B_c ne gouverne pas le seuil dans cette configuration : l'explication par anti-amplification est restreinte aux observations sur le plafond mesuré, sans prédiction hors échantillon. |
| Seuil déplacé mais ailleurs que prédit (E6 hors encadrement) | Le seuil dépend de B_c ; la formule 3·B_c − 28 n'est pas confirmée comme loi de position ; nous rapportons l'encadrement observé. |
| S1 conforme (k = 1 entre {t_amp} et {t_w}) | La fenêtre initiale seule ne suffit pas à expliquer le seuil QUIC observé. |
| E3 non conforme dans un bras | Résultat non interprétable ; diagnostic du banc avant toute publication. |
| Cas à B_c = 4 880 o présents (phénomène vu en S2) | Rapportés par connexion ; analyse de sensibilité sans ces connexions. |

La figure « escalier » des deux bras est publiée telle quelle.

## 8. Règles de conduite

- Aucune ouverture des durées avant la fin du bloc 20 **des deux bras**.
- Noyau, images Docker (identifiants de couche enregistrés au gel), gouverneur `performance`, `no_turbo = 1` et alimentation secteur fixés pendant toute la campagne ; un changement ⇒ bloc marqué et analyse de sensibilité. Aucun usage de `ALLOW_BATTERY` ni `ALLOW_TURBO`.
- Limite de blocs par jour levée (`--max-blocks-per-day 20`), décision consignée au journal avant le bloc 1 ; l'IC ne tient pas compte d'une corrélation entre blocs d'un même jour.
- Exclusions de blocs ou de cellules décidées sur critères **sans durée**, et listées.
- Données brutes (journaux + pcap + manifestes) archivées avant l'analyse. `Launcher_ext.sh` inchangé (empreinte au gel).

## 9. Limites déclarées d'avance

Un seul KEM (X448+ML-KEM-768), une seule signature (secp384r1, chaîne classique remplie), une seule implémentation (MsQuic épinglée), un seul couple de RTT, sans pertes, même machine et réseau émulé ; capture côté client.
L'intervention est un remplissage du ClientHello par extension privée : elle change B_c mais aussi le nombre de datagrammes du client et l'apparition d'un datagramme d'acquittement du serveur (§4) ; le calcul du client n'est pas isolé.
Une valeur de B_c ne se lit que par capture ; la campagne ne dit rien des pertes, de la reprise ni d'autres piles, ni de la conformité de MsQuic à la RFC 9000 §8.1.
Les cellules marquées « instables » par l'audit dans les cellules plafonnées de phase 0 relèvent probablement de la tolérance de l'audit (non vérifié).

## 10. Empreintes

Voir `seuil_S3/SHA256_GEL_S3.txt` (fichiers de gel des deux bras, plans, scripts, correctif, Dockerfile, lanceur, ce fichier, identifiants d'images). Commit / tag / dépôt horodaté : à renseigner dans l'article.
"""
    open(a.out, "w", encoding="utf-8").write(md)
    print("ecrit :", a.out, "(%d lignes)" % md.count("\n"))


if __name__ == "__main__":
    main()
