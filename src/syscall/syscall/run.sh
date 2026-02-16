#!/bin/bash

# Parse command line options
while getopts ":f:" opt; do
  case $opt in
    f)
      output_file="$OPTARG"
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
  esac
done

# Check if -f option is provided
if [ -z "$output_file" ]; then
  echo "Option -f is required." >&2
  exit 1
fi

# Check if output file exists
if [ ! -f "$output_file" ]; then
  echo "pid,execution_time" > "$output_file"
fi

# Run a.out command X times and append output to the specified file
for ((i=1; i<=100000; i++))
do
  ./bin/single -f "$output_file"
done
