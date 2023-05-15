#!/bin/bash
if [ $# -eq 0 ]; then
  echo "Usage: $0 <Files to be split>"
  exit 1
fi

LIB_FILE="$1"
if [ ! -f "$LIB_FILE" ]; then
  echo "Error: $LIB_FILE does not exist"
  exit 1
fi

# Remove debug and unnecessary sections, and create relocation and primary files
objcopy --strip-debug --strip-dwo --strip-unneeded "$LIB_FILE" "$LIB_FILE.relocation"
objcopy --remove-relocations=".*" "$LIB_FILE" "$LIB_FILE.prim"