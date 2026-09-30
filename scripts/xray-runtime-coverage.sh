#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
minimum="${XRAY_RUNTIME_FILE_COVERAGE_MIN:-90}"
profile_dir="$(mktemp -d)"
trap 'rm -rf "$profile_dir"' EXIT

if ! [[ "$minimum" =~ ^[0-9]+([.][0-9]+)?$ ]] || ! awk -v value="$minimum" 'BEGIN { exit !(value >= 0 && value <= 100) }'; then
	printf 'XRAY_RUNTIME_FILE_COVERAGE_MIN must be a number between 0 and 100; got %q\n' "$minimum" >&2
	exit 2
fi

cd "$repo_root/xray-runtime"
go test -count=1 -covermode=atomic -coverprofile="$profile_dir/runtime.out" ./internal/runtime
go test -count=1 -covermode=atomic -coverprofile="$profile_dir/cmd.out" ./cmd/xray-runtime

awk -v minimum="$minimum" '
  $1 == "mode:" { next }
  {
    file = $1
    sub(/:.*/, "", file)
    if (file ~ /\.pb\.go$/ || file ~ /_test\.go$/) next
    total[file] += $2
    if ($3 > 0) covered[file] += $2
  }
  END {
    failed = 0
    for (file in total) {
      percent = 100 * covered[file] / total[file]
      printf "%-62s %4d/%-4d %5.1f%%\n", file, covered[file], total[file], percent
      if (percent + 0.000001 < minimum) {
        printf "FAIL %s is below %.1f%%\n", file, minimum > "/dev/stderr"
        failed = 1
      }
    }
    if (length(total) == 0) {
      print "Xray runtime coverage profile contains no handwritten statements" > "/dev/stderr"
      exit 2
    }
    if (failed) exit 1
    print "PASS every handwritten Xray runtime Go file meets the coverage gate"
  }
' "$profile_dir/runtime.out" "$profile_dir/cmd.out"
