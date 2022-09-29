#!/bin/bash

# Auto-generate src/checkpoints.h for mainnet
# Output includes 144 headers, starting height
# and starting chainwork. This is sufficient to
# initialize hnsd chain sync from a non-genesis block.
# Requires local hsd full node and jq.
#
# Usage example:
# ./scripts/checkpoint.sh 135000

if [ $# -eq 0 ]
then
  echo "Usage: $0 <height>"
  exit 1
fi  

exec > ./src/checkpoints.h

start=$1
prev=$((start - 1))
end=$((start + 150))

echo "#ifndef _HSK_CHECKPOINTS_H"
echo "#define _HSK_CHECKPOINTS_H"
echo ""
echo "/*"
echo " * Main"
echo " */"
echo ""

echo "static const uint32_t HSK_CHECKPOINT_HEIGHT_MAIN = $start;"
echo ""

# Get total chainwork up to this point.
hash=$(hsd-rpc getblockhash $prev)
work=$(hsd-rpc getblockheader $hash | jq -r .chainwork)
echo "static const uint8_t HSK_CHECKPOINT_CHAINWORK_MAIN[32] ="
echo -n $work | \
  sed -e 's/\([0-9a-f][0-9a-f]\)/\\x\1/g' | \
  fold -w52 | \
  sed -e 's/^/  "/g' -e 's/$/"/g';
echo ";"
echo ""

echo "static const uint8_t HSK_CHECKPOINT_HEADERS_MAIN[][236] = {"

for (( i=$start; i<$end; i++ ))
do
  hash=$(hsd-rpc getblockhash $i);
  hex=$(hsd-rpc getblockheader $hash 0);
  echo "  // $i"
  echo -n $hex | \
    sed -e 's/\([0-9a-f][0-9a-f]\)/\\x\1/g' | \
    fold -w52 | \
    sed -e 's/^/  "/g' -e 's/$/"/g';
  echo ","
done

echo "};"
echo ""
echo "#endif"
