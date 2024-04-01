pragma circom 2.1.5;

// Given an input `in`, converts to a BigInt of k registers of n-bits
template ConvertBigInt(n,k) {
    signal input in;
    signal output out[k];

    signal sumOut[k];
    // TODO add RangeCheck here
    component rangeCheck[k];
    var mod = 2**n;
    var xTemp[k];
    for (var i=0; i < k; i++) {
        if (i == 0) {
            xTemp[i] = in;
        } else {
            xTemp[i] = xTemp[i-1] \ mod;
        }
        out[i] <-- xTemp[i] % mod;
        if (i == 0) {
            sumOut[i] <== out[i];
        } else {
            sumOut[i] <== out[i] * (1 << (n*i)) + sumOut[i-1];
        }
    }
    // Constraint to check that t = sum_i tBits[i] * 2^(n*i)
    sumOut[k-1] === in;
}