#!/bin/sh
#
# Derive SOURCE_DATE_EPOCH for VeraCrypt build and packaging paths.
# Precedence inside this helper is git HEAD, then the release date encoded in
# Common/Tcdefs.h. Callers remain responsible for honoring an explicit
# SOURCE_DATE_EPOCH before invoking this helper. The source root is resolved
# before probing Git so symlinked build paths still use the checkout HEAD,
# while release tarballs unpacked below unrelated repositories ignore the
# parent repository and fall back to Common/Tcdefs.h.

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <source-root>" >&2
    exit 2
fi

SOURCE_ROOT_INPUT=${1%/}
if [ -z "$SOURCE_ROOT_INPUT" ]; then
    SOURCE_ROOT_INPUT=/
fi
SOURCE_ROOT=$(cd "$SOURCE_ROOT_INPUT" 2>/dev/null && pwd -P) || {
    echo "Error: $1 is not a readable directory" >&2
    exit 1
}
TCDEFS_H="$SOURCE_ROOT/Common/Tcdefs.h"

GIT_WORKTREE=
GIT_SOURCE_PREFIX=
SOURCE_ROOT_BASENAME=${SOURCE_ROOT##*/}

if [ -e "$SOURCE_ROOT/.git" ]; then
    GIT_WORKTREE="$SOURCE_ROOT"
elif [ -e "$SOURCE_ROOT/../.git" ]; then
    GIT_WORKTREE=$(cd "$SOURCE_ROOT/.." 2>/dev/null && pwd -P)
    GIT_SOURCE_PREFIX="$SOURCE_ROOT_BASENAME/"
fi

GIT_EPOCH=
if [ -n "$GIT_WORKTREE" ] &&
    (cd "$GIT_WORKTREE" &&
        git rev-parse --is-inside-work-tree >/dev/null 2>&1 &&
        git ls-files --error-unmatch \
            "${GIT_SOURCE_PREFIX}Common/Tcdefs.h" \
            "${GIT_SOURCE_PREFIX}Build/Tools/source_date_epoch.sh" >/dev/null 2>&1); then
    GIT_EPOCH=$(cd "$GIT_WORKTREE" && git log -1 --pretty=%ct 2>/dev/null)
fi
case "$GIT_EPOCH" in
    ''|*[!0-9]*)
        ;;
    *)
        printf '%s\n' "$GIT_EPOCH"
        exit 0
        ;;
esac

if [ ! -r "$TCDEFS_H" ]; then
    echo "Error: $TCDEFS_H is not readable" >&2
    exit 1
fi

RELEASE_EPOCH=$(awk '
    function leap(y) { return ((y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)) }
    function mdays(m, y) { return (m == 2 ? 28 + leap(y) : (m == 4 || m == 6 || m == 9 || m == 11 ? 30 : 31)) }
    function epoch(y, m, d, days, i) {
        days = 0;
        for (i = 1970; i < y; i++) days += 365 + leap(i);
        for (i = 1; i < m; i++) days += mdays(i, y);
        days += d - 1;
        return days * 86400;
    }
    function is_number(value) { return (value ~ /^[0-9]+$/) }

    /^[[:space:]]*#define[[:space:]]+TC_RELEASE_DATE_YEAR[[:space:]]+/ {
        if (!is_number($3)) exit 1;
        year = $3 + 0;
        seen_year = 1;
    }
    /^[[:space:]]*#define[[:space:]]+TC_RELEASE_DATE_MONTH[[:space:]]+/ {
        if (!is_number($3)) exit 1;
        month = $3 + 0;
        seen_month = 1;
    }
    /^[[:space:]]*#define[[:space:]]+TC_RELEASE_DATE_DAY[[:space:]]+/ {
        if (!is_number($3)) exit 1;
        day = $3 + 0;
        seen_day = 1;
    }
    END {
        if (!seen_year || !seen_month || !seen_day) exit 1;
        if (year < 1970 || month < 1 || month > 12 || day < 1 || day > mdays(month, year)) exit 1;
        printf "%d", epoch(year, month, day);
    }' "$TCDEFS_H") || {
    echo "Error: unable to derive SOURCE_DATE_EPOCH from $TCDEFS_H" >&2
    exit 1
}

case "$RELEASE_EPOCH" in
    ''|*[!0-9]*)
        echo "Error: unable to derive SOURCE_DATE_EPOCH from $TCDEFS_H" >&2
        exit 1
        ;;
esac

printf '%s\n' "$RELEASE_EPOCH"
