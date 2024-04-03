pragma circom 2.1.5;

include "batch_ecdsa.circom";

component main = P256BatchECDSAVerifyNoPubkeyCheck(43, 6, 2);

// When b = 1 
// You get this error 
// error[T3001]: The size of the array is expected to be a usize
//    ┌─ "/home/dumbo/code/batch-ecdsa-secp256r1/circuits/batch_ecdsa.circom":54:5
//    │
// 54 │     component TPowersBigMult[b-2];
//    │     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ found here
//    │
//    = call trace:
//      ->P256BatchECDSAVerifyNoPubkeyCheck

// previous errors were found
// TL;DR: The size of the array is expected to be more than 1