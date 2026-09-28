#!/usr/bin/env bash
set -euo pipefail

profile="${1:-coverage.out}"

go test -count=1 -covermode=atomic -coverprofile="$profile" ./...

printf '\nHandwritten Go code by package (covered/total statements):\n'
awk '
  NR == 1 { next }
  {
    file = $1
    sub(/:.*/, "", file)
    if (file ~ /\.pb\.go$/) next
    package = file
    sub(/\/[^\/]+$/, "", package)
    sub(/^xray-easy\//, "", package)
    total[package] += $2
    if ($3 > 0) covered[package] += $2
  }
  END {
    for (package in total) {
      printf "%-35s %4d/%-4d %5.1f%%\n", package, covered[package], total[package], 100 * covered[package] / total[package]
    }
  }
' "$profile" | sort

printf '\nOverall statement coverage:\n'
awk '
  NR == 1 { next }
  {
    file = $1
    sub(/:.*/, "", file)
    all += $2
    if ($3 > 0) allCovered += $2
    if (file ~ /\.pb\.go$/) generated += $2
    else {
      handwritten += $2
      if ($3 > 0) handwrittenCovered += $2
    }
  }
  END {
    printf "All Go:       %d/%d = %.1f%%\n", allCovered, all, 100 * allCovered / all
    printf "Handwritten:  %d/%d = %.1f%%\n", handwrittenCovered, handwritten, 100 * handwrittenCovered / handwritten
    printf "Generated:    %d statements excluded from the handwritten metric\n", generated
  }
' "$profile"

printf '\nProfile: %s\n' "$profile"
