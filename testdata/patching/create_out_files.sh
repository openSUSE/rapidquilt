#!/bin/bash

# This script will take every "*.patch" file in current directory and generate
# either "*.out" or "*.error" files.
#
# "*.out" file contains the final content of the patched file
# "*.error" is empty file created when the patching fails

for PATCH in *.patch; do
    OUT_FILE="${PATCH%.patch}.out"
    ERROR_FILE="${PATCH%.patch}.error"

    rm -f "$OUT_FILE"
    rm -f "$ERROR_FILE"

    # Parse the fuzz parameter from patch headers (actually from whole patch, but we are careful about what we put in)
    fuzz=$(grep '^fuzz: ' "$PATCH" | sed 's/^fuzz: //')
    fuzz=${fuzz:-0}

    if patch -p0 --fuzz $fuzz --silent --output="$OUT_FILE" --reject-file=- < "$PATCH"; then
      echo "$PATCH -> $OUT_FILE"
    else
      rm -f "$OUT_FILE"
      touch "$ERROR_FILE"
      echo "$PATCH -> $ERROR_FILE"
    fi
done
