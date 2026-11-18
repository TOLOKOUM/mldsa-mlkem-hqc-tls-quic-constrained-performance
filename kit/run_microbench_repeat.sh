#!/usr/bin/env bash
# run_microbench_repeat.sh -- microbenchmarks KEM repetes, avec les conditions d'execution enregistrees (revue du 15/11/2026, point 4).
# A lancer DANS le conteneur des handshakes, avec les memes reglages (gouverneur, turbo, cpuset) que les campagnes.
# Usage : ./run_microbench_repeat.sh [out_dir] [repetitions=5] [secondes=10]
set -uo pipefail
OUT="${1:-microbench_repeat}"; N="${2:-5}"; SEC="${3:-10}"; mkdir -p "$OUT"; TS=$(date +%Y%m%d_%H%M%S)
{
  echo "date: $(date -Is)"; echo "kernel: $(uname -r)"; echo "cpu: $(grep -m1 'model name' /proc/cpuinfo)"
  echo "nproc: $(nproc)"; echo "cpuset: $(cat /sys/fs/cgroup/cpuset.cpus.effective 2>/dev/null || cat /proc/self/status | grep Cpus_allowed_list)"
  echo "governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo n/a)"
  echo "no_turbo: $(cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null || echo n/a)"
  echo "flags: $(grep -m1 flags /proc/cpuinfo | grep -o 'avx2\|avx512f\|bmi2\|pclmulqdq' | sort -u | tr '\n' ' ')"
  echo "openssl: $(openssl version)"; echo "liboqs: $(ls -l $(ldconfig -p | awk '/liboqs/{print $NF}' | head -1) 2>/dev/null)"
  echo "oqs-provider: $(openssl list -providers -provider oqsprovider -provider default 2>&1 | tr '\n' ' ')"
  echo "load: $(cat /proc/loadavg)"
} > "$OUT/conditions_$TS.txt"
for i in $(seq 1 "$N"); do
  for kem in mlkem768 hqc128 hqc192 hqc256; do        # ordre fixe ; relancer avec l'ordre inverse pour une deuxieme serie si besoin
    openssl speed -provider oqsprovider -provider default -seconds "$SEC" "$kem" > "$OUT/raw_${kem}_run${i}_$TS.txt" 2>&1
  done
done
echo "termine : $OUT (parser avec parse_microbench.py du depot ; calculer moyenne et ecart-type sur les $N series)"
