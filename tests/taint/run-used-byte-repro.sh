#!/bin/sh
set -eu

case "$(uname -m)" in
    x86_64)
        cc -O0 -g -o /tmp/used-byte-repro tests/taint/used-byte-repro.c
        ;;
    *)
        clang --target=x86_64-linux-gnu -nostdlib -static -fuse-ld=lld \
            -o /tmp/used-byte-repro tests/taint/used-byte-repro-x86_64.S
        ;;
esac

run_case() {
    mode=$1
    expected=$2
    output=$(printf 'ABCDEFGH' | ./afl-qemu-taint -- /tmp/used-byte-repro "$mode" 2>&1 || true)
    map=$(printf '%s\n' "$output" | sed -n '/^\[ /,$p' | tr -d '\n')

    case "$map" in
        *"$expected"*) ;;
        *)
            printf 'mode %s: expected map fragment %s\n' "$mode" "$expected" >&2
            printf '%s\n' "$output" >&2
            exit 1
            ;;
    esac
}

run_file_case() {
    mode=$1
    expected=$2
    input=/tmp/used-byte-taint-input

    printf 'ABCDEFGH' > "$input"
    output=$(AFL_TAINT_INPUT="$input" ./afl-qemu-taint -- \
        /tmp/used-byte-repro "$mode" "$input" 2>&1 || true)
    map=$(printf '%s\n' "$output" | sed -n '/^\[ /,$p' | tr -d '\n')

    case "$map" in
        *"$expected"*) ;;
        *)
            printf 'file mode %s: expected map fragment %s\n' "$mode" "$expected" >&2
            printf '%s\n' "$output" >&2
            exit 1
            ;;
    esac
}

run_trace_case() {
    mode=$1
    offset=$2

    output=$(printf 'ABCDEFGH' | AFL_TAINT_TRACE=1 ./afl-qemu-taint -- \
        /tmp/used-byte-repro "$mode" 2>&1 || true)

    if ! printf '%s\n' "$output" |
        grep -F '[TAINT_TRACE]' |
        grep -F "offset=$offset" |
        grep -F 'insn=' |
        grep -F 'mem_addr=' >/dev/null; then
        printf 'trace mode %s: missing offset %s trace with insn and mem_addr\n' \
            "$mode" "$offset" >&2
        printf '%s\n' "$output" >&2
        exit 1
    fi
}

run_case compare '[ !.......'
run_case arith '[ .!......'
run_case copy '[ ..!.....'
run_case index '[ ...!....'
run_case unused '[ ........'

run_file_case compare '[ !.......'
run_file_case unused '[ ........'

run_trace_case compare 0
run_trace_case arith 1
