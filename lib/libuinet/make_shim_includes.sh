#!/bin/sh

#
# 
#

dst_base=$1
src_base=$2
shift 2

if [ "$dst_base" = "" ] || [ "$src_base" = "" ] || [ "$1" = "" ]; then
    echo Usage: $0 shim_include_base src_dir_base rel_src_dir_1 [rel_src_dir_2 [rel_src_dir_3 ...]] 
    exit 1
fi

mkdir -p $dst_base

while [ "$1" != "" ]; do
    echo "  Processing $1"

    src_prefix=`dirname $1`
    find_base=`basename $1`

    if [ -d $src_base/$src_prefix/$find_base ]; then
	cd $src_base/$src_prefix

	for f in `find $find_base -name '*.h'`; do
	    dst_dir=$dst_base/$src_prefix/uinet_`dirname $f`
	    [ -d $dst_dir ] || mkdir -p $dst_dir
	    sed -r 's/(#include(_next)?[       ]+<)([^>]+\/)/\1uinet_\3/' < $f > $dst_dir/`basename $f`
	done
    else
	echo $src_base/$src_prefix/$find_base does not exist, skipping...
    fi

    shift;
done

