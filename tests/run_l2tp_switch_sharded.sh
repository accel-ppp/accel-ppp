#!/bin/sh
# Runs the l2tp_switch test files concurrently, one privileged container per
# shard, and fails if any shard fails.
#
#   tests/run_l2tp_switch_sharded.sh <image> [shards]
#
# <image> is a Linux image with accel-ppp built and installed and the test
# requirements present. Each container has its own network namespace, so
# shards do not compete for ports; the repository is mounted at /src.
# TSAN_OPTIONS, LSAN_OPTIONS, ASAN_OPTIONS and UBSAN_OPTIONS are forwarded to the
# containers (suppressions are in /src/tests/tsan.supp and lsan.supp).
# DOCKER_RUN_ARGS adds extra `docker run` arguments, e.g. --cpus=0.5 to
# imitate a slow CI runner.
# Shards run the binary baked into the image, so re-create it after rebuilding.
set -eu

image=${1:?usage: $0 <image> [shards]}
shards=${2:-5}
repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Balance by file size as a proxy for duration: biggest file first, each to
# the currently lightest shard.
python3 - "$repo/tests/accel-pppd/l2tp_switch" "$shards" "$work" <<'PY'
import glob, os, sys
directory, n, work = sys.argv[1], int(sys.argv[2]), sys.argv[3]
files = sorted(glob.glob(os.path.join(directory, "test_*.py")),
               key=os.path.getsize, reverse=True)
load = [0] * n
groups = [[] for _ in range(n)]
for f in files:
    i = load.index(min(load))
    groups[i].append("accel-pppd/l2tp_switch/" + os.path.basename(f))
    load[i] += os.path.getsize(f)
for i, g in enumerate(groups):
    if g:
        open(os.path.join(work, "shard%d" % i), "w").write(" ".join(g))
PY

pids=""
for shard in "$work"/shard*; do
    name=$(basename "$shard")
    # shellcheck disable=SC2086 # DOCKER_RUN_ARGS is meant to word-split
    docker run --rm --privileged ${DOCKER_RUN_ARGS:-} -v "$repo":/src \
        -e TSAN_OPTIONS -e LSAN_OPTIONS -e ASAN_OPTIONS -e UBSAN_OPTIONS "$image" sh -c \
        "cd /src/tests && python3 -m pytest -q -p no:cacheprovider -m l2tp_switch $(cat "$shard")" \
        >"$work/$name.log" 2>&1 &
    pids="$pids $! $name"
done

status=0
set -- $pids
while [ $# -gt 0 ]; do
    pid=$1 name=$2
    shift 2
    if wait "$pid"; then
        echo "$name: $(tail -n 1 "$work/$name.log")"
    else
        status=1
        echo "$name: FAILED"
        cat "$work/$name.log"
    fi
done
exit $status
