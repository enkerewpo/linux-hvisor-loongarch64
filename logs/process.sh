#!/bin/bash

set -e

INPUT_LOG="$1"

if [ -z "$INPUT_LOG" ] || [ ! -f "$INPUT_LOG" ]; then
    echo "usage: $0 <log_file>"
    exit 1
fi

OUTPUT_DIR="processed"
mkdir -p "$OUTPUT_DIR"

BASENAME=$(basename "$INPUT_LOG")
OUTPUT_LOG="$OUTPUT_DIR/filtered_$BASENAME"


grep 'hvisor::arch::loongarch64' "$INPUT_LOG" | grep 'generic mmio handler' > "$OUTPUT_LOG"

echo "output: $OUTPUT_LOG"