#!/bin/bash

if [ "$#" -ne 4 ]; then
  echo "Usage: $0 -file events.log -searchkeyword <keyword>"
  exit 1
fi

while [ "$#" -gt 0 ]; do
  case "$1" in
    -file)
      FILE="$2"
      shift 2
      ;;
    -searchkeyword)
      KEYWORD="$2"
      shift 2
      ;;
    *)
      echo "Invalid option: $1" >&2
      echo "Usage: $0 -file events.log -searchkeyword <keyword>"
      exit 1
      ;;
  esac
done

if [ -z "$FILE" ] || [ -z "$KEYWORD" ]; then
  echo "Both -file and -searchkeyword options must be provided"
  echo "Usage: $0 -file events.log -searchkeyword <keyword>"
  exit 1
fi

awk -v keyword="$KEYWORD" '
/^\[NEW EVENT FOUND\]/ { if (event ~ keyword) print event; event = "" } 
{ event = event $0 "\n" }
END { if (event ~ keyword) print event }
' "$FILE"
