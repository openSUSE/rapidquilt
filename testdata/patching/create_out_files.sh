#!/bin/bash

for PATCH in *.patch; do
    OUT_FILE="${PATCH%.patch}.out"
    echo "$PATCH -> $OUT_FILE"
    patch -p0 --silent --output="$OUT_FILE" < "$PATCH"
done
