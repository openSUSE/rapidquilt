#!/bin/bash

for PATCH in *.patch; do
    OUT_FILE="${PATCH%.patch}.out"
    ERROR_FILE="${PATCH%.patch}.error"

    rm -f "$OUT_FILE"
    rm -f "$ERROR_FILE"

    if patch -p0 --fuzz 0 --silent --output="$OUT_FILE" --reject-file=- < "$PATCH"; then
      echo "$PATCH -> $OUT_FILE"
    else
      rm -f "$OUT_FILE"
      touch "$ERROR_FILE"
      echo "$PATCH -> $ERROR_FILE"
    fi
done
