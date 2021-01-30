#!/usr/bin/env bash

# dir = $PROJECT_DIR
# parentdir=$(dirname "$dir")

workspace="$HOME/XCBuildLogParser"
logfile="${workspace}/post-action.log"
if [[ -e $logfile ]]; then
  rm $logfile
fi
exec > $logfile 2>&1
echo $BUILD_DIR