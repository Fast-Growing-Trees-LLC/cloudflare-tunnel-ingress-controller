#!/usr/bin/env bash
# Render assertions for the chart. The controller flags are built by template
# conditionals, and a conditional that silently drops a flag turns a documented
# switch into a no-op, so the rendered command list is worth asserting.
set -euo pipefail

CHART="$(dirname "$0")/../helm/cloudflare-tunnel-ingress-controller"
failures=0

render() {
  helm template render-test "${CHART}" "$@" |
    awk '/^ +command:/,/^ +env:/' |
    sed -n 's/^ *- //p'
}

# assert <description> <expected|-> <arguments...>
# An expected value of "-" asserts the flag is absent.
assert_resync() {
  local description="$1" expected="$2"
  shift 2
  local rendered actual
  rendered="$(render "$@")"
  actual="$(printf '%s\n' "${rendered}" | sed -n 's/^--access-resync-interval=//p')"
  if [[ "${expected}" == "-" ]]; then
    if [[ -n "${actual}" ]]; then
      echo "FAIL: ${description}: expected no --access-resync-interval, rendered ${actual}"
      failures=$((failures + 1))
      return
    fi
  elif [[ "${actual}" != "${expected}" ]]; then
    echo "FAIL: ${description}: expected --access-resync-interval=${expected}, rendered ${actual:-nothing}"
    failures=$((failures + 1))
    return
  fi
  echo "ok: ${description}"
}

# the value documented as the off switch has to reach the binary, 0 disables
# the resync while an omitted flag falls back to the controller default of 10m
assert_resync "resyncInterval 0 disables the resync" "0" \
  --set access.enabled=true --set access.resyncInterval=0
assert_resync "quoted 0 disables the resync" "0" \
  --set access.enabled=true --set-string access.resyncInterval=0
assert_resync "0s disables the resync" "0s" \
  --set access.enabled=true --set-string access.resyncInterval=0s
assert_resync "the chart default is passed through" "10m" \
  --set access.enabled=true
assert_resync "an explicit interval is passed through" "30m" \
  --set access.enabled=true --set-string access.resyncInterval=30m
# time.ParseDuration("") is an error, so an empty value must leave the flag off
assert_resync "an empty interval emits no flag" "-" \
  --set access.enabled=true --set-string access.resyncInterval=
assert_resync "access disabled emits no access flag at all" "-" \
  --set access.resyncInterval=30m

# the whole point of the feature being opt in: a default install renders the
# same command list it rendered before Access existed
if render | grep -q -- '--access'; then
  echo "FAIL: the default values render an --access flag"
  failures=$((failures + 1))
else
  echo "ok: the default values render no --access flag"
fi

if [[ "${failures}" -gt 0 ]]; then
  echo "${failures} chart render assertion(s) failed"
  exit 1
fi
