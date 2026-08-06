#!/usr/bin/env bash
# Run the full test suite. Host-safe: every test works against fixture trees
# and a throwaway state directory.
set -Eeuo pipefail
HERE=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -P -- "${HERE}/.." && pwd)

FIX=${SDB_TEST_FIXTURES:-"${ROOT}/tests/.fixtures"}
export SDB_TEST_FIXTURES=$FIX
printf 'building fixtures in %s\n\n' "$FIX"
rm -rf -- "$FIX"
bash "${ROOT}/tests/fixtures/make-fixtures.sh" "$FIX" >/dev/null

failed=0
for t in "${ROOT}"/tests/test-*.sh; do
    printf '\n--- %s ---\n' "${t##*/}"
    bash "$t" || failed=$((failed + 1))
done

printf '\n=====================================\n'
if ((failed == 0)); then
    printf 'all test files passed\n'
else
    printf '%d test file(s) FAILED\n' "$failed"
fi
exit "$failed"
