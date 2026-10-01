#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
minimum="${XRAY_RUNTIME_FILE_COVERAGE_MIN:-90}"
profile_dir="${XRAY_RUNTIME_COVERAGE_DIR:-}"
remove_profile_dir=0
if [[ -z "$profile_dir" ]]; then
	profile_dir="$(mktemp -d)"
	remove_profile_dir=1
fi
mkdir -p "$profile_dir"
if [[ "$remove_profile_dir" == "1" ]]; then
	trap 'rm -rf "$profile_dir"' EXIT
fi
test_json="${GO_TEST_JSON:-}"

if ! [[ "$minimum" =~ ^[0-9]+([.][0-9]+)?$ ]] || ! awk -v value="$minimum" 'BEGIN { exit !(value >= 0 && value <= 100) }'; then
	printf 'XRAY_RUNTIME_FILE_COVERAGE_MIN must be a number between 0 and 100; got %q\n' "$minimum" >&2
	exit 2
fi

cd "$repo_root/xray-runtime"
# Keep -count=1 out so Go can reuse successful results from GOCACHE.
run_go_tests() {
	if [[ -n "$test_json" ]]; then
		mkdir -p "$(dirname -- "$test_json")"
		if [[ "${GO_TEST_RACE:-0}" == "1" ]]; then
			go test -json -race "$@" | tee "$test_json" >/dev/null
		else
			go test -json "$@" | tee "$test_json" >/dev/null
		fi
	elif [[ "${GO_TEST_RACE:-0}" == "1" ]]; then
		go test -race "$@"
	else
		go test "$@"
	fi
}
run_go_tests -covermode=atomic -coverprofile="$profile_dir/runtime.out" ./...

awk -v minimum="$minimum" '
  $1 == "mode:" { next }
  {
    file = $1
    sub(/:.*/, "", file)
    if (file ~ /\.pb\.go$/ || file ~ /_test\.go$/) next
    if (file !~ /\/internal\/runtime\// && file !~ /\/cmd\/xray-runtime\//) next
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
' "$profile_dir/runtime.out"
