#!/usr/bin/env bash
set -euo pipefail

profile="${1:-coverage.out}"
overall_min="${BACKEND_COVERAGE_MIN:-90}"
package_min="${BACKEND_PACKAGE_COVERAGE_MIN:-90}"
test_json="${GO_TEST_JSON:-}"

validate_threshold() {
	local name="$1"
	local value="$2"
	if ! [[ "$value" =~ ^[0-9]+([.][0-9]+)?$ ]] || ! awk -v value="$value" 'BEGIN { exit !(value >= 0 && value <= 100) }'; then
		printf '%s must be a number between 0 and 100; got %q\n' "$name" "$value" >&2
		exit 2
	fi
}

validate_threshold BACKEND_COVERAGE_MIN "$overall_min"
validate_threshold BACKEND_PACKAGE_COVERAGE_MIN "$package_min"

# Limit the profile to project packages. npm dependencies can contain unrelated
# Go modules (for example web/node_modules/flatted/golang) that ./... discovers.
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
run_go_tests -covermode=atomic -coverprofile="$profile" ./cmd/... ./internal/...

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

printf '\nCoverage gates (handwritten code): overall >= %s%%; each package >= %s%%\n' "$overall_min" "$package_min"
awk -v overall_min="$overall_min" -v package_min="$package_min" '
  NR == 1 { next }
  {
    file = $1
    sub(/:.*/, "", file)
    if (file ~ /\.pb\.go$/) next
    package = file
    sub(/\/[^\/]+$/, "", package)
    sub(/^xray-easy\//, "", package)
    total[package] += $2
    handwritten += $2
    if ($3 > 0) {
      covered[package] += $2
      handwrittenCovered += $2
    }
  }
  END {
    failed = 0
    for (package in total) {
      percent = 100 * covered[package] / total[package]
      if (percent + 0.000001 < package_min) {
        printf "FAIL %-35s %.1f%% is below %.1f%%\n", package, percent, package_min > "/dev/stderr"
        failed = 1
      }
    }
    overall = 100 * handwrittenCovered / handwritten
    if (overall + 0.000001 < overall_min) {
      printf "FAIL handwritten overall %.1f%% is below %.1f%%\n", overall, overall_min > "/dev/stderr"
      failed = 1
    }
    if (failed) exit 1
    printf "PASS handwritten overall %.1f%%; all handwritten packages meet %.1f%%\n", overall, package_min
  }
' "$profile"

printf '\nProfile: %s\n' "$profile"
