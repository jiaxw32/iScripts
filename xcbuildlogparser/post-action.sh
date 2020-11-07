#!/usr/bin/env bash

logfile="${PROJECT_DIR}/XCBuildLogParser/post-action.log"
if [[ -e $logfile ]]; then
  rm $logfile
fi
exec > $logfile 2>&1
echo $BUILD_DIR