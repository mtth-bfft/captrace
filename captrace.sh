#!/bin/bash

set -euo pipefail

usage() {
    echo "Usage: captrace.sh [-h] [-f] [-r] [-p <pid>] [-t <tracefs>]" >&2
    echo "" >&2
    echo "  -h            display this help text" >&2
    echo "  -f            display capabilities used by forked processes" >&2
    echo "  -r            display raw events without formatting" >&2
    echo "  -p <pid>      only show capabilities used by one process" >&2
    echo "  -t <tracefs>  use the given tracefs filesystem" >&2
    echo "                (default is to use /sys/kernel/debug/tracing" >&2
    exit 1
}

TRACEFS="/sys/kernel/debug/tracing"
TARGET_PID=""
TRACEOPTS="noevent-fork"
PRETTIFY=1
while getopts "frvp:t:" o; do
    case "${o}" in
        p) TARGET_PID=${OPTARG} ;;
        f) TRACEOPTS="event-fork" ;;
        t) TRACEFS=${OPTARG} ;;
        r) PRETTIFY=0 ;;
        *) usage ;;
    esac
done

if ! [ -d "$TRACEFS" ] || ! [ -f "$TRACEFS/trace_pipe" ]; then
    echo "Error: captrace.sh requires a mounted tracefs" >&2
    echo "You can specify its location using -t /sys/kernel/..." >&2
    exit 1
fi

function cleanup() {
    [ -d "$TRACEFS" ] || return
    ! [ -d "$TRACEFS/events/kprobes/captrace" ] || echo 0 > "$TRACEFS/events/kprobes/captrace/enable"
    echo '-:captrace' > "$TRACEFS/kprobe_events" 2>/dev/null || /bin/true
    echo > "$TRACEFS/set_event_pid"
    echo 0 > "$TRACEFS/tracing_on"
}

trap cleanup EXIT

(echo 0 > "$TRACEFS/events/kprobes/captrace/enable") 2>/dev/null || /bin/true
echo '-:captrace' >> "$TRACEFS/kprobe_events" 2>/dev/null || /bin/true

echo 'p:captrace cap_capable arg3=%dx arg4=%r10 arg5=%r8' > "$TRACEFS/kprobe_events"
echo "$TARGET_PID" > "$TRACEFS/set_event_pid"
echo "$TRACEOPTS" > "$TRACEFS/trace_options"
echo 1 > "$TRACEFS/events/kprobes/captrace/enable"
echo 1 > "$TRACEFS/tracing_on"

if [ $PRETTIFY -ne 0 ]; then
    cat "$TRACEFS/trace_pipe" | sed -ru 's/\s*([^[]+)\s.+\s+([0-9.]+):?.+arg3=0?x?ffff.+arg4=(0?x?[0-9a-f]+).+arg5=(0?x?[0-9a-f]+)$/\2\t\1\tcap=\3\topts=\4/I' | sed -ru 's/\s*([^[]+)\s.+\s+([0-9.]+):?.+arg3=(0?x?[0-9a-f]+).+arg4=(0?x?[0-9a-f]+).+$/\2\t\1\tcap=\3\topts=\4/I'
else
    cat "$TRACEFS/trace_pipe"
fi
