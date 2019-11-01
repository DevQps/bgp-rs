#!/bin/bash
set -e

cargo install --force honggfuzz
for TARGET in fuzz_targets/*.rs; do
	FILENAME=$(basename $TARGET)
	FILE="${FILENAME%.*}"
	export HFUZZ_RUN_ARGS="--exit_upon_crash -v -n2 -N1000000"
	HFUZZ_BUILD_ARGS="--features honggfuzz_fuzz" cargo hfuzz run $FILE
	if [ -f hfuzz_workspace/$FILE/HONGGFUZZ.REPORT.TXT ]; then
		cat hfuzz_workspace/$FILE/HONGGFUZZ.REPORT.TXT
		for CASE in hfuzz_workspace/$FILE/SIG*; do
			cat $CASE | xxd -p
		done
		exit 1
	fi
done
