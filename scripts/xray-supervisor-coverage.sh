#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
minimum="${SUPERVISOR_FILE_COVERAGE_MIN:-90}"
profile_dir="$(mktemp -d)"
trap 'rm -rf "$profile_dir"' EXIT

if ! [[ "$minimum" =~ ^[0-9]+([.][0-9]+)?$ ]] || ! awk -v value="$minimum" 'BEGIN { exit !(value >= 0 && value <= 100) }'; then
	printf 'SUPERVISOR_FILE_COVERAGE_MIN must be a number between 0 and 100; got %q\n' "$minimum" >&2
	exit 2
fi

cd "$repo_root"
go test -count=1 -covermode=atomic -coverprofile="$profile_dir/cmd.out" ./cmd/xray-supervisor
go test -count=1 -covermode=atomic -coverprofile="$profile_dir/client.out" ./internal/supervisor

awk -v minimum="$minimum" '
  NR == 1 { next }
  {
    file = $1
    sub(/:.*/, "", file)
    if ($1 == "mode:" || file ~ /\.pb\.go$/ || file ~ /_test\.go$/) next
    if ($2 == 0) next
    total[file] += $2
    if ($3 > 0) covered[file] += $2
  }
  END {
    failed = 0
    for (file in total) {
      percent = 100 * covered[file] / total[file]
      printf "%-55s %4d/%-4d %5.1f%%\n", file, covered[file], total[file], percent
      if (percent + 0.000001 < minimum) {
        printf "FAIL %s is below %.1f%%\n", file, minimum > "/dev/stderr"
        failed = 1
      }
    }
    if (failed) exit 1
    print "PASS every handwritten supervisor source file meets the coverage gate"
  }
' "$profile_dir/cmd.out" "$profile_dir/client.out"
