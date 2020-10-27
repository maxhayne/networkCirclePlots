#!/bin/bash
usage()
{
    echo "usage: makeCirclePlots [[[-outlierFile outlierFile] [-sort sortParameter] [-outputFileType outputFileType]] | [-h]]"
}

while [ "$1" != "" ]; do
    case $1 in
        -outlierFile )          shift
                                outlierFile=" ${1} "
                                ;;
        -sort )                 shift
                                sortParameter=" ${1} "
                                ;;
        -outputFileType )             shift
                                outputFileType=" ${1} "
                                ;;
        -h | --help )           usage
                                exit
                                ;;
        * )                     usage
                                exit 1
    esac
    shift
done
# Test code to verify command line processing
echo "outlierFile is: $outlierFile"
echo "sort is: $sortParameter"
echo "outputFileType is: $outputFileType"
argString="${outlierFile}${sortParameter}${outputFileType}"
echo "argString is: ${argString}"
i=1
result=1
start=$SECONDS
for i in $(find . -type f -name "*outliers.tsv")
do
    echo $i
    Rscript /data/circlePlots/new/DataFrameCircs_MaxV1.R $i cluster png 
done
duration=$(( SECONDS - start ))
echo $duration