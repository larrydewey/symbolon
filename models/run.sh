#!/usr/bin/env bash
# Re-run every model (SPEC Section 27.5) and fail if any lemma or query is
# not verified. Run inside `nix develop` so the pinned tool versions are used.
#
#   ./run.sh                 every model
#   ./run.sh log.spthy ...   the named models only
#
# MODEL_HEAP sets the Tamarin heap (default 8g); L-01 models need no more.
# A model may carry extra prover flags in a sibling file `<model>.args`
# (for example `--heuristic=O --oracle=log.oracle`). Per-model output goes
# to `out/<model>.txt`.

set -uo pipefail
cd "$(dirname "$0")"
mkdir -p out

timeout_s="${MODEL_TIMEOUT:-3600}"
heap="${MODEL_HEAP:-8g}"
models=("$@")
if [ ${#models[@]} -eq 0 ]; then
  mapfile -t models < <(ls *.spthy *.pv *.ocv 2>/dev/null)
fi

status=0
for m in "${models[@]}"; do
  args=()
  [ -f "$m.args" ] && read -r -a args < "$m.args"
  out="out/$m.txt"
  printf '== %s\n' "$m"
  case "$m" in
    *.spthy)
      # One lemma per run: a lemma that does not finish inside the timeout
      # must not hide the ones that do.
      mapfile -t lemmas < <(grep -o '^lemma [A-Za-z0-9_]*' "$m" | awk '{print $2}')
      for l in "${lemmas[@]}"; do
        lout="out/$m.$l.txt"
        timeout "$timeout_s" tamarin-prover +RTS -M"$heap" -RTS --prove="$l" "${args[@]}" "$m" > "$lout" 2>&1
        rc=$?
        # Summary lines look like: "  name (all-traces): verified (12 steps)".
        # Only this lemma's line counts: the file still lists the others,
        # most of them "analysis incomplete" because they were not proved.
        line=$(grep -E "^  $l \((all-traces|exists-trace)\):" "$lout" | head -1)
        printf '  %s\n' "${line:-none}"
        if [ $rc -ne 0 ] || ! printf '%s' "$line" | grep -q 'verified' \
           || grep -q 'WARNING: .* wellformedness' "$lout"; then
          echo "  FAIL ($m:$l; see $lout)"; status=1
        fi
      done
      ;;
    *.pv)
      timeout "$timeout_s" proverif "${args[@]}" "$m" > "$out" 2>&1
      rc=$?
      grep -E '^(RESULT|Query)' "$out" | grep -v '^Query .* is true\.$' | sed 's/^/  /' | sort -u
      if [ $rc -ne 0 ] || grep -qE '^RESULT .*(is false|cannot be proved)' "$out" \
         || ! grep -q '^RESULT' "$out"; then
        echo "  FAIL ($m; see $out)"; status=1
      fi
      ;;
    *.ocv)
      timeout "$timeout_s" cryptoverif "${args[@]}" "$m" > "$out" 2>&1
      rc=$?
      grep -E '^(All queries proved|RESULT)' "$out" | sed 's/^/  /'
      if [ $rc -ne 0 ] || ! grep -q '^All queries proved' "$out"; then
        echo "  FAIL ($m; see $out)"; status=1
      fi
      ;;
  esac
done

# EasyCrypt proofs (computational layer).
if [ $# -eq 0 ] && [ -d ec ]; then
  for f in ec/*.ec; do
    [ -e "$f" ] || continue
    printf '== %s\n' "$f"
    if ! timeout "$timeout_s" easycrypt compile "$f" > "out/$(basename "$f").txt" 2>&1; then
      echo "  FAIL ($f)"; status=1
    else
      echo "  checked"
    fi
  done
fi

exit $status
