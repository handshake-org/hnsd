#!/bin/bash

# Auto-generate src/checkpoints.h for mainnet
# Output includes 150 headers, starting height
# and starting chainwork. This is sufficient to
# initialize hnsd chain sync from a non-genesis block.
# Requires local hsd full node and jq.
#
# Usage example:
# ./scripts/checkpoint.sh 136000

if [ $# -eq 0 ]
then
  echo "Usage: $0 <height>"
  exit 1
fi  

exec > ./src/checkpoints.h

start=$1
prev=$((start - 1))
end=$((start + 150))

# Get total chainwork up to this point.
hash=$(hsd-rpc getblockhash $prev)
work=$(hsd-rpc getblockheader $hash | jq -r .chainwork)

echo "#ifndef _HSK_CHECKPOINTS_H"
echo "#define _HSK_CHECKPOINTS_H"
echo ""
echo "#include \"store.h\""
echo ""
echo "/*"
echo " * Main"
echo " */"
echo ""
echo "static const uint8_t HSK_CHECKPOINT_MAIN[HSK_STORE_CHECKPOINT_SIZE] = {"

echo "  // height ($start)"
printf '  "%08x"\n' $start | \
  sed -e 's/\([0-9a-f][0-9a-f]\)/\\x\1/g'

echo "  // chainwork"
echo $work | \
  sed -e 's/\([0-9a-f][0-9a-f]\)/\\x\1/g' | \
  fold -w52 | \
  sed -e 's/^/  "/g' -e 's/$/"/g';

echo "  // headers..."
for (( i=$start; i<$end; i++ ))
do
  hash=$(hsd-rpc getblockhash $i);
  hex=$(hsd-rpc getblockheader $hash 0);
  echo "  // $i"
  echo $hex | \
    sed -e 's/\([0-9a-f][0-9a-f]\)/\\x\1/g' | \
    fold -w52 | \
    sed -e 's/^/  "/g' -e 's/$/"/g';
done

echo "};"
echo ""
echo "#endif"
