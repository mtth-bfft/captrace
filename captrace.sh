#!/bin/sh

# Copyright 2018-2019 Matthieu Buffet
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software
# is furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

set -eu

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

echo 'p:captrace ns_capable_common userns=%di cap=%si audit=%dx' > "$TRACEFS/kprobe_events"
echo "$TARGET_PID" > "$TRACEFS/set_event_pid"
echo "$TRACEOPTS" > "$TRACEFS/trace_options"
echo 1 > "$TRACEFS/events/kprobes/captrace/enable"
echo 1 > "$TRACEFS/tracing_on"

if [ $PRETTIFY -ne 0 ]; then
    sed -rn 's/ *([^[]+) *\[[0-9]+\][ .]*([0-9.]+):?.*(userns=[0-9xa-f]+).*(cap=[0-9xa-f]+).*(audit=[0-9xa-f]+).*/\2\t\1\t\4\t\3\t\5/p' "$TRACEFS/trace_pipe"
else
    cat "$TRACEFS/trace_pipe"
fi
