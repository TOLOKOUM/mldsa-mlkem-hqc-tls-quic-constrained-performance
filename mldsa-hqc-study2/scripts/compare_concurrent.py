#!/usr/bin/env python3
"""
compare_concurrent.py
Compare plusieurs niveaux de concurrence (10, 50, 100, 500 clients).

Usage:
    python3 compare_concurrent.py <results_parent_dir> [--output comparison_report]
    python3 compare_concurrent.py <results_parent_dir> --throughput  # Ajoute les graphiques de throughput

Le répertoire parent doit contenir plusieurs sous-répertoires de résultats
(chaque sous-répertoire = un niveau de concurrence ou un scénario).
"""

import os
import sys
import csv
import glob
import argparse
import json
from collections import defaultdict

import numpy as np

# Importer les fonctions utilitaires du script d'analyse
from analyse_concurrent import load_client_csv, compute_stats


def find_result_dirs(parent_dir):
    """Trouve tous les sous-répertoires contenant des résultats concurrents."""
    result_dirs = []
    for root, dirs, files in os.walk(parent_dir):
        csv_files = [f for f in files if f.startswith('client_') and f.endswith('.csv')]
        if csv_files:
            result_dirs.append(root)
    return sorted(result_dirs)


def parse_dir_name(dirname):
    """Parse le nom d'un répertoire de résultats pour extraire les paramètres."""
    # Format attendu: {proto}_c{num}_{profile}_l{loss}_d{delay}_{timestamp}[_classic|_hqc]
    basename = os.path.basename(dirname)
    parts = basename.split('_')
    info = {
        'protocol': '?', 
        'num_clients': '?', 
        'profile': '?', 
        'loss': '?', 
        'delay': '?',
        'test_type': 'pq'  # pq, classic, hqc
    }
    
    # Détection du type de test
    if basename.endswith('_classic'):
        info['test_type'] = 'classic'
        basename = basename[:-8]  # Enlever _classic
    elif basename.endswith('_hqc'):
        info['test_type'] = 'hqc'
        basename = basename[:-5]  # Enlever _hqc
        parts = basename.split('_')
    
    try:
        info['protocol'] = parts[0]
        for p in parts[1:]:
            if p.startswith('c') and p[1:].isdigit():
                info['num_clients'] = p[1:]
            elif p.startswith('l') and p[1:].isdigit():
                info['loss'] = p[1:]
            elif p.startswith('d') and p[1:].isdigit():
                info['delay'] = p[1:]
            elif p in ('none', 'simple', 'stable', 'unstable'):
                info['profile'] = p
    except (IndexError, ValueError):
        pass
    return info


def load_metadata(rdir):
    """Charge les métadonnées d'un répertoire de résultats."""
    meta = {}
    meta_files = glob.glob(os.path.join(rdir, "metadata_*.txt"))
    for mf in meta_files:
        with open(mf, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('#') or not line:
                    continue
                if '=' in line:
                    k, v = line.split('=', 1)
                    meta[k.strip()] = v.strip()
    return meta


def compare_directories(result_dirs, output_dir=None, show_throughput=False):
    """Compare les résultats de plusieurs répertoires de tests concurrents."""
    
    if output_dir is None:
        output_dir = os.path.commonpath(result_dirs) if len(result_dirs) > 1 else os.path.dirname(result_dirs[0])

    all_summaries = []

    for rdir in result_dirs:
        info = parse_dir_name(rdir)
        csv_files = sorted(glob.glob(os.path.join(rdir, "client_*_*.csv")))
        meta = load_metadata(rdir)

        if not csv_files:
            continue

        # Regrouper par (sig_alg, kem_alg)
        groups = defaultdict(list)
        for f in csv_files:
            basename = os.path.basename(f)
            parts = basename.replace('.csv', '').split('_')
            if len(parts) >= 4:
                sig_alg = parts[2]
                kem_alg = '_'.join(parts[3:])
                groups[(sig_alg, kem_alg)].append(f)

        for (sig_alg, kem_alg), files in groups.items():
            all_durations = []
            total_success = 0
            total_attempts = 0

            for f in files:
                durations, successes = load_client_csv(f)
                all_durations.extend(durations)
                total_success += sum(successes)
                total_attempts += len(successes)

            stats = compute_stats(all_durations)
            stats['sig_alg'] = sig_alg
            stats['kem_alg'] = kem_alg
            stats['num_clients'] = info['num_clients']
            stats['protocol'] = info['protocol']
            stats['profile'] = info['profile']
            stats['loss'] = info['loss']
            stats['delay'] = info['delay']
            stats['test_type'] = info['test_type']
            stats['total_success'] = total_success
            stats['total_attempts'] = total_attempts
            stats['success_rate'] = total_success / total_attempts * 100 if total_attempts else 0
            stats['throughput'] = meta.get('throughput_handshakes_per_sec', 'N/A')
            stats['total_time_ms'] = meta.get('total_time_ms', 'N/A')
            stats['dir'] = rdir
            all_summaries.append(stats)

    if not all_summaries:
        print("[ERROR] Aucune donnée trouvée.")
        return

    # ── Afficher le tableau comparatif (enrichi) ───────────────────────────
    print(f"\n{'='*140}")
    print(f"  COMPARAISON MULTI-NIVEAUX DE CONCURRENCE")
    print(f"{'='*140}")
    print(f"{'Type':<8} {'Proto':<6} {'Clients':<8} {'Profil':<10} {'Loss':<6} {'Delay':<8} "
          f"{'Sig':<10} {'KEM':<12} {'Succès':<8} {'Throughput':<12} {'Médiane':<10} {'P95':<10}")
    print(f"{'-'*140}")

    # Trier par type de test, protocole, puis nombre de clients
    all_summaries.sort(key=lambda x: (x['test_type'], x['protocol'], 
                                       int(x['num_clients']) if x['num_clients'].isdigit() else 0))

    for s in all_summaries:
        # Formater le throughput
        thr = s['throughput']
        if thr != 'N/A':
            try:
                thr = f"{float(thr):.1f}"
            except:
                pass
        
        print(f"{s['test_type']:<8} {s['protocol']:<6} {s['num_clients']:<8} {s['profile']:<10} "
              f"{s['loss']:<6} {s['delay']:<8} {s['sig_alg']:<10} {s['kem_alg']:<12} "
              f"{s['success_rate']:>6.1f}% {thr:>12} {s['median']:>8.2f}  {s['p95']:>8.2f}")

    print(f"{'='*140}")

    # ── Sauvegarder le tableau comparatif (enrichi) ────────────────────────
    comparison_csv = os.path.join(output_dir, "comparison_concurrent.csv")
    with open(comparison_csv, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['test_type', 'protocol', 'num_clients', 'profile', 'loss_percent', 'delay_ms',
                         'sig_alg', 'kem_alg', 'success_rate', 'throughput_hs_s', 'total_time_ms',
                         'median_ms', 'mean_ms', 'p95_ms', 'p99_ms', 'min_ms', 'max_ms', 'std_ms',
                         'total_handshakes', 'total_success'])
        for s in all_summaries:
            writer.writerow([
                s['test_type'], s['protocol'], s['num_clients'], s['profile'], s['loss'], s['delay'],
                s['sig_alg'], s['kem_alg'], f"{s['success_rate']:.1f}",
                s['throughput'], s['total_time_ms'],
                f"{s['median']:.2f}", f"{s['mean']:.2f}", f"{s['p95']:.2f}",
                f"{s['p99']:.2f}", f"{s['min']:.2f}", f"{s['max']:.2f}", f"{s['std']:.2f}",
                s['total_attempts'], s['total_success']
            ])
    print(f"\n[CSV] Tableau comparatif : {comparison_csv}")

    # ── Générer les plots comparatifs ──────────────────────────────────────
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
    except ImportError:
        print("[PLOTS] matplotlib non disponible.")
        return

    # Regrouper par scénario pour les plots
    scenarios = defaultdict(list)
    for s in all_summaries:
        scenario_key = f"{s['test_type']}_{s['protocol']}_{s['profile']}_l{s['loss']}_d{s['delay']}"
        scenarios[scenario_key].append(s)

    for scenario_key, items in scenarios.items():
        items.sort(key=lambda x: int(x['num_clients']) if x['num_clients'].isdigit() else 0)

        client_counts = [int(it['num_clients']) for it in items]
        medians = [it['median'] for it in items]
        p95s = [it['p95'] for it in items]
        p99s = [it['p99'] for it in items]
        success_rates = [it['success_rate'] for it in items]
        
        # Récupérer les throughputs (convertir en float)
        throughputs = []
        for it in items:
            thr = it['throughput']
            if thr != 'N/A':
                try:
                    throughputs.append(float(thr))
                except:
                    throughputs.append(0)
            else:
                throughputs.append(0)

        # Créer une figure avec 2 ou 3 sous-graphiques
        if show_throughput and any(t > 0 for t in throughputs):
            fig, axes = plt.subplots(1, 3, figsize=(18, 5))
        else:
            fig, axes = plt.subplots(1, 2, figsize=(14, 5))
            axes = list(axes) + [None]  # Pour uniformiser l'indexation

        # 1. Latence vs nombre de clients
        axes[0].plot(client_counts, medians, 'o-', label='Médiane', linewidth=2, markersize=8)
        axes[0].plot(client_counts, p95s, 's--', label='P95', linewidth=2, markersize=8)
        axes[0].plot(client_counts, p99s, '^:', label='P99', linewidth=2, markersize=8)
        axes[0].set_xlabel('Nombre de clients simultanés')
        axes[0].set_ylabel('Durée handshake (ms)')
        axes[0].set_title(f'Latence vs Concurrence — {scenario_key}')
        axes[0].legend()
        axes[0].grid(True, alpha=0.3)
        axes[0].set_xscale('log')
        axes[0].set_xticks(client_counts)
        axes[0].set_xticklabels(client_counts)

        # 2. Taux de succès vs nombre de clients
        axes[1].plot(client_counts, success_rates, 'D-', color='green', linewidth=2, markersize=8)
        axes[1].set_xlabel('Nombre de clients simultanés')
        axes[1].set_ylabel('Taux de succès (%)')
        axes[1].set_title(f'Taux de succès vs Concurrence — {scenario_key}')
        axes[1].grid(True, alpha=0.3)
        axes[1].set_xscale('log')
        axes[1].set_xticks(client_counts)
        axes[1].set_xticklabels(client_counts)
        axes[1].set_ylim(0, 105)

        # 3. Throughput vs nombre de clients (optionnel)
        if show_throughput and axes[2] is not None and any(t > 0 for t in throughputs):
            axes[2].plot(client_counts, throughputs, 'o-', color='purple', linewidth=2, markersize=8)
            axes[2].set_xlabel('Nombre de clients simultanés')
            axes[2].set_ylabel('Throughput (handshakes/s)')
            axes[2].set_title(f'Throughput vs Concurrence — {scenario_key}')
            axes[2].grid(True, alpha=0.3)
            axes[2].set_xscale('log')
            axes[2].set_xticks(client_counts)
            axes[2].set_xticklabels(client_counts)

        plt.tight_layout()
        safe_name = scenario_key.replace('/', '_').replace(' ', '_')
        plot_file = os.path.join(output_dir, f"comparison_{safe_name}.pdf")
        plt.savefig(plot_file, dpi=150, bbox_inches='tight')
        plt.close()
        print(f"[PLOT] {plot_file}")


def main():
    parser = argparse.ArgumentParser(description='Comparaison multi-niveaux de concurrence')
    parser.add_argument('parent_dir', help='Répertoire parent contenant les sous-répertoires de résultats')
    parser.add_argument('--output', '-o', default=None, help='Répertoire de sortie pour les fichiers générés')
    parser.add_argument('--throughput', action='store_true', 
                        help='Inclure les graphiques de throughput vs concurrence')
    args = parser.parse_args()

    if not os.path.isdir(args.parent_dir):
        print(f"[ERROR] Répertoire introuvable : {args.parent_dir}")
        sys.exit(1)

    result_dirs = find_result_dirs(args.parent_dir)
    print(f"[INFO] {len(result_dirs)} répertoires de résultats trouvés :")
    for d in result_dirs:
        info = parse_dir_name(d)
        print(f"  - {os.path.basename(d)}  (type={info['test_type']}, proto={info['protocol']}, "
              f"clients={info['num_clients']}, profil={info['profile']}, "
              f"loss={info['loss']}%, delay={info['delay']}ms)")

    output_dir = args.output or args.parent_dir
    os.makedirs(output_dir, exist_ok=True)
    compare_directories(result_dirs, output_dir, show_throughput=args.throughput)


if __name__ == '__main__':
    main()
