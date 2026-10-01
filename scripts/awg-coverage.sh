#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"
profile="${1:-$repo_root/awg-service/coverage.out}"
minimum="${AWG_COVERAGE_MIN:-90}"
test_json="${GO_TEST_JSON:-}"

if ! [[ "$minimum" =~ ^[0-9]+([.][0-9]+)?$ ]] || ! awk -v value="$minimum" 'BEGIN { exit !(value >= 0 && value <= 100) }'; then
	printf 'AWG_COVERAGE_MIN must be a number between 0 and 100; got %q\n' "$minimum" >&2
	exit 2
fi

cd "$repo_root/awg-service"
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
run_go_tests -covermode=atomic -coverprofile="$profile" ./...

awk -v minimum="$minimum" '
  NR == 1 { next }
  {
    file = $1
    sub(/:.*/, "", file)
    if (file ~ /\.pb\.go$/) next
    total += $2
    if ($3 > 0) covered += $2
  }
  END {
    if (total == 0) {
      print "AWG coverage profile contains no handwritten statements" > "/dev/stderr"
      exit 2
    }
    percent = 100 * covered / total
    printf "AWG handwritten Go code: %d/%d = %.2f%% (module gate >= %s%%)\n", covered, total, percent, minimum
    if (percent + 0.000001 < minimum) {
      printf "FAIL AWG module coverage %.2f%% is below %.2f%%\n", percent, minimum > "/dev/stderr"
      exit 1
    }
    print "PASS AWG module coverage gate"
  }
' "$profile"

printf 'Profile: %s\n' "$profile"
