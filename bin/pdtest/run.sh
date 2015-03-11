#!/bin/sh

if1=$1
if2=$2
num_queues=4

qno=0
cpuno=0
test_args="--gpool 40000"
while [ $qno -lt $num_queues ]
do
    test_args="$test_args --netmap $if2:$qno --gen --iqlen 4096 --txcpu $cpuno --rxcpu $cpuno"
    qno=`expr $qno + 1`
    cpuno=`expr $cpuno + 1`
done

qno=0
while [ $qno -lt $num_queues ]
do
    test_args="$test_args --netmap $if1:$qno --bridge $if2:$qno --txcpu $cpuno --rxcpu $cpuno"
    qno=`expr $qno + 1`
    cpuno=`expr $cpuno + 1`
done

echo ./pdtest $test_args
sudo ./pdtest $test_args
