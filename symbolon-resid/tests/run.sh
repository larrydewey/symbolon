#!/usr/bin/env bash
# Runs every Symbolon test suite with the Resid checkout's compiler, whose
# standard library (../resid/lib) carries the CGGMP modules Symbolon needs
# (lib/cggmp_blind.resid is not in an older ~/.resid install).
# --verify-lib-dev: lib/verify/tpm.resid gained tpm_verify_certify and
# tpm_ak_pubkey (2026-10-29) and is not yet re-pinned in the compiler.
set -euo pipefail
cd "$(dirname "$0")/.."
RC="${RESIDC:-$HOME/git/larry/resid/build/boot/residc}"
fail=0
for t in $(find src -name '*_test.resid' | sort); do
    case "$t" in src/net/net_test.resid) continue ;; esac   # needs the services: tests/net_e2e.sh
    line=$( (ulimit -v 40000000; ulimit -s unlimited; export RESID_MEM_LIMIT=10000; timeout 1500 "$RC" test "$t" --verify-lib-dev) 2>&1 | grep 'Failures:' || echo "Failures: build error")
    echo "$t: $line"
    case "$line" in *"Failures: 0 "*) ;; *) fail=1 ;; esac
done
echo "src/net/net_test.resid (services): $(tests/net_e2e.sh 2>&1 | grep 'Failures:' || echo 'Failures: e2e error')"
echo "tests/cli_e2e.sh: $(tests/cli_e2e.sh 2>&1 | grep -E "PASS|FAIL" | head -1)"
echo "tests/cli_e2e.sh (TLS): $(TLS=1 tests/cli_e2e.sh 2>&1 | grep -E "PASS|FAIL" | head -1)"
echo "tests/tpm_e2e.sh: $(tests/tpm_e2e.sh 2>&1 | grep -E "PASS|FAIL|SKIP" | head -1)"
echo "tests/home_e2e.sh: $(tests/home_e2e.sh 2>&1 | grep -E "PASS|FAIL" | head -1)"
echo "tests/share_e2e.sh: $(tests/share_e2e.sh 2>&1 | grep -E "PASS|FAIL" | head -1)"
echo "tests/org_e2e.sh: $(tests/org_e2e.sh 2>&1 | grep -E "PASS|FAIL" | head -1)"
echo "tests/store_e2e.sh: $(tests/store_e2e.sh 2>&1 | grep -E "PASS|FAIL" | head -1)"
echo "tests/rotate_e2e.sh: $(tests/rotate_e2e.sh 2>&1 | grep -E "PASS|FAIL|SKIP" | head -1)"
echo "tests/browser_e2e.sh: $(tests/browser_e2e.sh 2>&1 | grep -E "PASS|FAIL|SKIP" | head -1)"
echo "tests/ssh_e2e.sh: $(tests/ssh_e2e.sh 2>&1 | grep -E "PASS|FAIL|SKIP" | head -1)"
echo "tests/fido_e2e.sh: $(tests/fido_e2e.sh 2>&1 | grep -E "PASS|FAIL|SKIP" | head -1)"
echo "tests/link_e2e.sh: $(tests/link_e2e.sh 2>&1 | grep -E "PASS|FAIL|SKIP" | head -1)"
echo "tests/fido_usb.sh (by hand, a key plugged in): $(tests/fido_usb.sh 2>&1 | grep -E "PASS|FAIL|SKIP" | head -1)"
exit $fail
