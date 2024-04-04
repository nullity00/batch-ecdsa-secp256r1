pragma circom 2.0.5;

include "../../circuits/batch_ecdsa.circom";

component main  {public [r, rprime, s, msghash, pubkey]}  = P256BatchECDSAVerifyNoPubkeyCheck(43, 6, 4);