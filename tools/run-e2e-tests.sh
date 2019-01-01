#!/bin/sh -e

if [ $# -ne 1 ] ; then
	echo "Usage: $0 MODE" >&2
	exit 1
fi

BASEDIR=`dirname $0`
E2E_DIR=$BASEDIR/../e2e
MODE="$1"

for TEST in $E2E_DIR/[0-9]*.sh ; do
	TEST=`basename -s .sh $TEST`
	"$BASEDIR/run-e2e-test.sh" $MODE $TEST
done
