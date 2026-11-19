#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""make_experiment_manifest.py -- manifeste des experiences S2 et S3 : une ligne par jeu de donnees, plus la liste des empreintes SHA-256 de chaque fichier.
Sorties (dans --out, defaut MANIFEST_S2_S3/) :
  S2_S3_EXPERIMENT_MANIFEST.csv   une ligne par jeu (campagne, famille, phase, dossiers, nombre de fichiers, octets, journaux, connexions, pcap, dates, empreinte agregee)
  S2_S3_DATA_SHA256SUMS.txt       « sha256  chemin » pour chaque fichier des jeux (ordre des octets, comme LC_ALL=C sort)
Empreinte agregee : sha256 de la liste « sha256  chemin » triee (les dossiers captures + etat du jeu, passes dans cet ordre), equivalente a
  (find CAPTURES ETAT -type f | LC_ALL=C sort | xargs sha256sum) | sha256sum
Mode --verify : recalcule les empreintes de S2_S3_DATA_SHA256SUMS.txt et signale toute difference (donnees modifiees ou manquantes).
Usage : python3 kit/make_experiment_manifest.py [--out MANIFEST_S2_S3] [--verify]"""
import argparse, csv, datetime, hashlib, os, re, subprocess, sys

# (id, campagne, famille, phase, captures, etat, gel, plan, analyse)
SETS = [
    ("S2_p0_TLS_IW4", "S2", "TLS_IW4", "phase0 (dossier sans suffixe ; voir JOURNAL_PHASE0)", "captures_S2_phase0_TLS_IW4", "campaign_state_S2_phase0_TLS_IW4", "seuil_S2/freeze_S2_TLS_IW4", "", ""),
    ("S2_p0_TLS_IW4_r50", "S2", "TLS_IW4", "phase0 (suffixe r50)", "captures_S2_phase0_TLS_IW4_r50", "campaign_state_S2_phase0_TLS_IW4_r50", "seuil_S2/freeze_S2_TLS_IW4", "", ""),
    ("S2_p0_TLS_IW4_rtt50", "S2", "TLS_IW4", "phase0 (suffixe rtt50)", "captures_S2_phase0_TLS_IW4_rtt50", "campaign_state_S2_phase0_TLS_IW4_rtt50", "seuil_S2/freeze_S2_TLS_IW4", "", ""),
    ("S2_p0_TLS_IW20_r50", "S2", "TLS_IW20", "phase0 (RTT 50)", "captures_S2_phase0_TLS_IW20_r50", "campaign_state_S2_phase0_TLS_IW20_r50", "seuil_S2/freeze_S2_TLS_IW20", "", ""),
    ("S2_p0_QUIC_C", "S2", "QUIC_C", "phase0 (RTT 0)", "captures_S2_phase0_QUIC_C", "campaign_state_S2_phase0_QUIC_C", "seuil_S2/freeze_S2_QUIC_C", "", ""),
    ("S2_p0_QUIC_C_rtt50", "S2", "QUIC_C", "phase0 (RTT 50)", "captures_S2_phase0_QUIC_C_rtt50", "campaign_state_S2_phase0_QUIC_C_rtt50", "seuil_S2/freeze_S2_QUIC_C", "", ""),
    ("S2_TLS_IW4", "S2", "TLS_IW4", "mesure (20 blocs)", "captures_S2_TLS_IW4", "campaign_state_S2_TLS_IW4", "seuil_S2/freeze_S2_TLS_IW4", "seuil_S2/plans_S2_TLS_IW4/plan_S2_all.csv", "analysis_S2_TLS_IW4"),
    ("S2_TLS_IW20", "S2", "TLS_IW20", "mesure (20 blocs)", "captures_S2_TLS_IW20", "campaign_state_S2_TLS_IW20", "seuil_S2/freeze_S2_TLS_IW20", "seuil_S2/plans_S2_TLS_IW20/plan_S2_all.csv", "analysis_S2_TLS_IW20"),
    ("S2_QUIC_C", "S2", "QUIC_C", "mesure (20 blocs)", "captures_S2_QUIC_C", "campaign_state_S2_QUIC_C", "seuil_S2/freeze_S2_QUIC_C", "seuil_S2/plans_S2_QUIC_C/plan_S2_all.csv", "analysis_S2_QUIC_C"),
    ("S3_p0_PAD0", "S3", "QUIC_PAD0 (temoin)", "phase0 (RTT 50)", "captures_S3_phase0_PAD0", "campaign_state_S3_phase0_PAD0", "seuil_S3/freeze_draft_PAD1", "seuil_S3/plans_draft_PAD1/plan_S2_phase0.csv", ""),
    ("S3_p0_PAD1", "S3", "QUIC_PAD1 (traitement)", "phase0 (RTT 50)", "captures_S3_phase0_PAD1", "campaign_state_S3_phase0_PAD1", "seuil_S3/freeze_draft_PAD1", "seuil_S3/plans_draft_PAD1/plan_S2_phase0.csv", ""),
    ("S3_PAD0", "S3", "QUIC_PAD0 (temoin)", "mesure (20 blocs)", "captures_S3_PAD0", "campaign_state_S3_PAD0", "seuil_S3/freeze_S3_PAD0", "seuil_S3/plans_S3_PAD0/plan_S2_all.csv", "analysis_S3_PAD0"),
    ("S3_PAD1", "S3", "QUIC_PAD1 (traitement)", "mesure (20 blocs)", "captures_S3_PAD1", "campaign_state_S3_PAD1", "seuil_S3/freeze_S3_PAD1", "seuil_S3/plans_S3_PAD1/plan_S2_all.csv", "analysis_S3_PAD1"),
]
PUBLISHED = {"S2_QUIC_C": "6c79101f05fc12d983f14e9962ed05a3f587208d224a8cab618da72549feacab"}   # valeur citee au supplement S6


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def files_of(dirs):
    out = []
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for r, _, fs in os.walk(d):
            for n in fs:
                out.append(os.path.join(r, n))
    return sorted(out, key=lambda s: s.encode())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="MANIFEST_S2_S3"); ap.add_argument("--verify", action="store_true")
    a = ap.parse_args()
    sums = os.path.join(a.out, "S2_S3_DATA_SHA256SUMS.txt")
    if a.verify:
        bad = n = 0
        for ln in open(sums, encoding="utf-8"):
            h, p = ln.rstrip("\n").split("  ", 1); n += 1
            if not os.path.exists(p) or sha256_file(p) != h:
                bad += 1; print("DIFFERENT OU MANQUANT :", p)
        print("verifies : %d fichiers, %d ecarts" % (n, bad)); sys.exit(1 if bad else 0)
    os.makedirs(a.out, exist_ok=True)
    rows, allsum, seen = [], [], set()
    for sid, camp, fam, phase, cap, st, frz, plan, ana in SETS:
        if not os.path.isdir(cap):
            print("ABSENT :", cap); continue
        fl = files_of([cap, st])
        lines, tot = [], 0
        for p in fl:
            h = sha256_file(p); tot += os.path.getsize(p); lines.append("%s  %s\n" % (h, p))
            if p not in seen:
                seen.add(p); allsum.append("%s  %s\n" % (h, p))
        agg = hashlib.sha256("".join(lines).encode()).hexdigest()
        logs = [p for p in fl if "/handshake_logs/" in p and p.endswith(".log")]
        nconn = 0
        for p in logs:
            with open(p, errors="replace") as f:
                nconn += sum(1 for ln in f if ln.startswith("Execution "))
        mt = [os.path.getmtime(p) for p in fl]
        d = lambda t: datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%d")
        rows.append(dict(id=sid, campagne=camp, famille=fam, phase=phase, captures=cap, etat=st, gel=frz, plan=plan, analyse=ana,
                         fichiers=len(fl), octets=tot, journaux_handshake=len(logs), connexions_journalisees=nconn,
                         pcap=sum(1 for p in fl if p.endswith(".pcap")), premiere_ecriture_utc=d(min(mt)), derniere_ecriture_utc=d(max(mt)),
                         sha256_agrege=agg, sha256_publie=PUBLISHED.get(sid, ""),
                         archive_existante=(cap + ".tar.gz") if os.path.exists(cap + ".tar.gz") else "",
                         archive_sha256=sha256_file(cap + ".tar.gz") if os.path.exists(cap + ".tar.gz") else ""))
        print("%-20s %6d fichiers %12d o %7d connexions  %s" % (sid, len(fl), tot, nconn, agg[:16]))
        if sid in PUBLISHED:
            leg = subprocess.run("find %s %s -type f | sort | xargs sha256sum | sha256sum" % (cap, st), shell=True, capture_output=True, text=True).stdout.split()[0]
            print("   valeur publiee %s... ; commande historique (ordre du systeme) %s... ; version C %s... -> %s" % (
                PUBLISHED[sid][:16], leg[:16], agg[:16], "CONCORDE" if PUBLISHED[sid] in (leg, agg) else "NE CONCORDE PAS"))
    with open(os.path.join(a.out, "S2_S3_EXPERIMENT_MANIFEST.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    with open(sums, "w", encoding="utf-8") as fh:
        fh.writelines(allsum)
    print("ecrit : %s/S2_S3_EXPERIMENT_MANIFEST.csv (%d jeux) et S2_S3_DATA_SHA256SUMS.txt (%d fichiers)" % (a.out, len(rows), len(allsum)))


if __name__ == "__main__":
    main()
