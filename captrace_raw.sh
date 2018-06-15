#!/bin/bash -eu

# Copyright 2018 Matthieu Buffet
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

usage() { echo "Usage: captrace.sh [-v] [-f] [-p <pid>] [-t <tracefs>]" 1>&2; exit 1; }

TARGET_PID=""
TRACEOPTS="noevent-fork"
TRACEFS="/sys/kernel/debug/tracing"
while getopts "vfp:" o; do
    case "${o}" in
        p) TARGET_PID=${OPTARG} ;;
        f) TRACEOPTS="event-fork" ;;
	t) TRACEFS=${OPTARG} ;;
        *) usage ;;
    esac
done

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

sed -rn 's/captrace *: *\([^)]+\) +//p' "$TRACEFS/trace_pipe"
