#!/bin/bash
# Copies the Reconix engine into the app assets before building.
# Run from the android/ folder:  ./prepare-assets.sh
set -e
DEST="app/src/main/assets/reconix"
rm -rf "$DEST" && mkdir -p "$DEST"
cp ../engine/app.py ../engine/webscan.py "$DEST/"
cp -r ../engine/wscan ../engine/rules ../engine/assets "$DEST/"
find "$DEST" -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
echo "Assets prepared in $DEST"
