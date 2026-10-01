#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 5 || $# -gt 6 ]]; then
	printf 'usage: %s MODULE_DIR LABEL PROFILE REPORT_DIR TEST_JSON [METRIC_MODE]\n' "$0" >&2
	exit 2
fi

module_dir="$1"
label="$2"
profile="$3"
report_dir="$4"
test_json="$5"
metric_mode="${6:-all}"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$report_dir"

coverage_txt="$report_dir/coverage.txt"
coverage_html="$report_dir/coverage.html"
junit_xml="$report_dir/junit.xml"
test_summary="$report_dir/test-summary.md"

if [[ -f "$profile" ]]; then
	if (cd "$module_dir" && go tool cover -func="$profile") > "$coverage_txt"; then
		(cd "$module_dir" && go tool cover -html="$profile" -o "$coverage_html") || true
	else
		printf 'Coverage profile could not be read.\n' > "$coverage_txt"
	fi
else
	printf 'Coverage profile was not produced because the test command failed before coverage collection.\n' > "$coverage_txt"
fi

python3 "$script_dir/go-test-json-to-junit.py" "$test_json" "$junit_xml" "$test_summary"

summary_file="${GITHUB_STEP_SUMMARY:-$report_dir/summary.md}"
{
	echo "## Go test report — $label"
	echo
	if [[ -f "$profile" ]]; then
		metric_line="$(awk -v mode="$metric_mode" '
			$1 == "mode:" { next }
			{
				file = $1
				sub(/:.*/, "", file)
				if (mode == "handwritten" && file ~ /\.pb\.go$/) next
				if (mode == "xray-runtime" && (file ~ /\.pb\.go$/ || file ~ /_test\.go$/ || (file !~ /\/internal\/runtime\// && file !~ /\/cmd\/xray-runtime\//))) next
				total += $2
				if ($3 > 0) covered += $2
			}
			END {
				if (total == 0) print "unavailable"
				else printf "%.1f%% (%d/%d statements, %s)", 100 * covered / total, covered, total, mode
			}
		' "$profile")"
		printf 'Coverage: `%s`\n' "$metric_line"
	else
		echo "Coverage: unavailable"
	fi
	echo
	cat "$test_summary"
	echo 'Artifacts: `coverage.html`, `coverage.txt`, `coverage.out`, `junit.xml`'
	echo
} >> "$summary_file"
