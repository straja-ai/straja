#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <metrics_log_path>" >&2
  exit 2
fi

log_path="$1"
if [[ ! -f "$log_path" ]]; then
  echo "metrics log not found: $log_path" >&2
  exit 1
fi

print_ensemble() {
  local lines
  lines="$(sed -nE 's/^METRICS category=([^ ]+) threshold=([^ ]+) (.*)$/\1\t\2\t\3/p' "$log_path" | sort)"
  if [[ -z "$lines" ]]; then
    echo "No ensemble metrics found."
    return
  fi

  echo "Ensemble Metrics"
  printf "%-20s %-6s %5s %4s %4s %4s %4s %8s %8s %8s %8s %10s %10s %10s %10s\n" \
    "Category" "Thr" "N" "TP" "FP" "TN" "FN" "Prec" "Recall" "F1" "Acc" "LatAvg" "LatP50" "LatP95" "LatMax"
  echo "--------------------------------------------------------------------------------------------------------------------------------------------"
  while IFS=$'\t' read -r category threshold json; do
    [[ -z "$category" ]] && continue
    values="$(jq -r '[.n,.tp,.fp,.tn,.fn,.precision,.recall,.f1,.accuracy,.latency_avg_ms,.latency_p50_ms,.latency_p95_ms,.latency_max_ms] | @tsv' <<<"$json")"
    IFS=$'\t' read -r n tp fp tn fn precision recall f1 accuracy lat_avg lat_p50 lat_p95 lat_max <<<"$values"
    printf "%-20s %-6s %5d %4d %4d %4d %4d %8.4f %8.4f %8.4f %8.4f %10.2f %10.2f %10.2f %10.2f\n" \
      "$category" "$threshold" "$n" "$tp" "$fp" "$tn" "$fn" \
      "$precision" "$recall" "$f1" "$accuracy" "$lat_avg" "$lat_p50" "$lat_p95" "$lat_max"
  done <<<"$lines"
}

print_detectors() {
  local lines
  lines="$(sed -nE 's/^DETECTOR_METRICS category=([^ ]+) detector=([^ ]+) threshold=([^ ]+) (.*)$/\1\t\2\t\3\t\4/p' "$log_path" | sort)"
  if [[ -z "$lines" ]]; then
    echo "No detector metrics found."
    return
  fi

  echo ""
  echo "Detector Metrics"
  printf "%-20s %-30s %-6s %6s %6s %6s %4s %4s %4s %4s %8s %8s %8s %8s %10s %10s %10s %10s\n" \
    "Category" "Detector" "Thr" "NTotal" "NValid" "NInv" "TP" "FP" "TN" "FN" "Prec" "Recall" "F1" "Acc" "LatAvg" "LatP50" "LatP95" "LatMax"
  echo "-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------"
  while IFS=$'\t' read -r category detector threshold json; do
    [[ -z "$category" ]] && continue
    values="$(jq -r '[.n_total,.n_valid,.n_invalid,.tp,.fp,.tn,.fn,.precision,.recall,.f1,.accuracy,.latency_avg_ms,.latency_p50_ms,.latency_p95_ms,.latency_max_ms] | @tsv' <<<"$json")"
    IFS=$'\t' read -r n_total n_valid n_invalid tp fp tn fn precision recall f1 accuracy lat_avg lat_p50 lat_p95 lat_max <<<"$values"
    printf "%-20s %-30s %-6s %6d %6d %6d %4d %4d %4d %4d %8.4f %8.4f %8.4f %8.4f %10.2f %10.2f %10.2f %10.2f\n" \
      "$category" "$detector" "$threshold" "$n_total" "$n_valid" "$n_invalid" \
      "$tp" "$fp" "$tn" "$fn" "$precision" "$recall" "$f1" "$accuracy" \
      "$lat_avg" "$lat_p50" "$lat_p95" "$lat_max"
  done <<<"$lines"
}

print_ensemble
print_detectors
