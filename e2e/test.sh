#!/bin/sh -e

if [ $# -ne 1 ] ; then
	echo "Usage: $0 MODE" >&2
	exit 1
fi

BASEDIR=`dirname $0`
MODE="$1"

for TEST in $BASEDIR/[0-9]*.sh ; do
	TEST=`basename -s .sh $TEST`
	"$BASEDIR/test1.sh" $MODE $TEST
done
