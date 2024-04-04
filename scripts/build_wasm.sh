#!/bin/bash

BATCH_SIZE=2
PHASE1=../ptau/powersOfTau28_hez_final_25.ptau
CIRCUIT_NAME=ecdsa_main
BUILD_DIR=build
OUTPUT_DIR="$BUILD_DIR"/"$CIRCUIT_NAME"_js
HOME_DIR=~
NODE_PATH="$HOME_DIR"/node/out/Release/node
SNARKJS_PATH="$HOME_DIR"/snarkjs/cli.js

if [ -f "./ptau/powersOfTau28_hez_final_25.ptau" ]; then
    echo "Found Phase 1 ptau file"
else
    echo "No Phase 1 ptau file found. Exiting..."
    exit 1
fi

if [ ! -d "$BUILD_DIR" ]; then
    echo "No build directory found. Creating build directory..."
    mkdir "$BUILD_DIR"
fi

echo $PWD

echo "****COMPILING CIRCUIT****"
start=`date +%s`
# circom "circuits/$CIRCUIT_NAME".circom --O0 --c --output "$BUILD_DIR"
circom "circuits/$CIRCUIT_NAME".circom --O1 --r1cs --sym --wasm --output "$BUILD_DIR"
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****COMPILING WASM WITNESS GENERATION CODE****"
start=`date +%s`
cd "$OUTPUT_DIR"
node generate_witness.js "$CIRCUIT_NAME".wasm ../../scripts/output/input_"$BATCH_SIZE".json ../witness.wtns
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****VERIFYING WITNESS****"
start=`date +%s`
cd ..
"$SNARKJS_PATH" wtns check "$CIRCUIT_NAME".r1cs witness.wtns
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****GENERATING ZKEY 0****"
start=`date +%s`
"$NODE_PATH" --trace-gc --trace-gc-ignore-scavenger --max-old-space-size=2048000 --initial-old-space-size=2048000 --no-global-gc-scheduling --no-incremental-marking --max-semi-space-size=1024 --initial-heap-size=2048000 --expose-gc "$SNARKJS_PATH" zkey new "$CIRCUIT_NAME".r1cs "$PHASE1" "$CIRCUIT_NAME"_0.zkey -v
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****CONTRIBUTE TO PHASE 2 CEREMONY****"
start=`date +%s`
"$NODE_PATH" "$SNARKJS_PATH" zkey contribute -verbose "$CIRCUIT_NAME"_0.zkey "$CIRCUIT_NAME".zkey -n="First phase2 contribution" -e="some random text 5555" > contribute.out
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****VERIFYING FINAL ZKEY****"
start=`date +%s`
"$NODE_PATH" --trace-gc --trace-gc-ignore-scavenger --max-old-space-size=2048000 --initial-old-space-size=2048000 --no-global-gc-scheduling --no-incremental-marking --max-semi-space-size=1024 --initial-heap-size=2048000 --expose-gc "$SNARKJS_PATH" zkey verify -verbose "$CIRCUIT_NAME".r1cs "$PHASE1" "$CIRCUIT_NAME".zkey > verify.out
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****EXPORTING VKEY****"
start=`date +%s`
"$NODE_PATH" "$SNARKJS_PATH" zkey export verificationkey "$CIRCUIT_NAME".zkey vkey.json -v
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****GENERATING PROOF FOR SAMPLE INPUT****"
start=`date +%s`
"$NODE_PATH" "$SNARKJS_PATH" groth16 prove "$CIRCUIT_NAME".zkey witness.wtns proof.json public.json > proof.out
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****VERIFYING PROOF FOR SAMPLE INPUT****"
start=`date +%s`
"$NODE_PATH" "$SNARKJS_PATH" groth16 verify vkey.json public.json proof.json -v
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****SIZE OF PROVING KEY****"
stat -c %s "$CIRCUIT_NAME".zkey | awk '{print $0/1024/1024/1024}'