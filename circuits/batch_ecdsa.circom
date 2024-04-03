pragma circom 2.1.5;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "./circom-ecdsa-p256/circuits/ecdsa.circom";
include "./circom-ecdsa-p256/circuits/circom-pairing/circuits/bigint.circom";
include "p256_lc.circom";
include "p256_ops.circom";
include "utils.circom";

template P256BatchECDSAVerifyNoPubkeyCheck(n, k, b) {
    // Assertions
    assert(k >= 2);
    assert(k <= 100);

    // Signals
    signal input r[b][k];
    signal input rprime[b][k];
    signal input s[b][k];
    signal input msghash[b][k];
    signal input pubkey[b][2][k];
    signal output result;

    // Variables
    var p[100] = get_p256_prime(n, k); // pse/circom-ecdsa-p256/p256_func.circom
    var order[100] = get_p256_order(n, k); // pse/circom-ecdsa-p256/p256_func.circom
    var sinv_comp[b][50];
    signal sinv[b][k];

    // Use poseidon hash to get a random t for summations
    component MultiHasher[b][k];
    for (var i=0; i < b; i++) {
        for (var j=0; j < k; j++) {
            MultiHasher[i][j] = Poseidon(6); // iden3/circomlib/poseidon.circom
            MultiHasher[i][j].inputs[0] <== r[i][j];
            MultiHasher[i][j].inputs[1] <== s[i][j];
            MultiHasher[i][j].inputs[2] <== msghash[i][j];
            MultiHasher[i][j].inputs[3] <== pubkey[i][0][j];
            MultiHasher[i][j].inputs[4] <== pubkey[i][1][j];
            if (i == 0 && j == 0 ) {
                MultiHasher[i][j].inputs[5] <== 0;
            } else if (j == 0) {
                MultiHasher[i][j].inputs[5] <== MultiHasher[i-1][j].out;
            } else {
                MultiHasher[i][j].inputs[5] <== MultiHasher[i][j-1].out;
            }
        }
    }

    // Compute powers of t
    signal t;
    t <== MultiHasher[b-1][k-1].out;
    signal TPowersBits[b][k];
    component tToBigInt = ConvertBigInt(n, k); // puma314/batch-ecdsa/bigint_ext.circom
    component TPowersBigMult[b-2];
    tToBigInt.in <== t;
    for (var i=0; i < b; i++) {
        if (i == 0) {
            TPowersBits[0][0] <== 1;
            for (var j=1; j < k; j++) {
                TPowersBits[0][j] <== 0;
            }
        } else if (i == 1) {
            for (var j=0; j < k; j++) {
                TPowersBits[1][j] <== tToBigInt.out[j];
            }
        } else {
            TPowersBigMult[i-2] = BigMultModP(n,k); // circom-pairing/bigint.circom
            for (var j=0; j < k; j++) {
                TPowersBigMult[i-2].a[j] <== tToBigInt.out[j];
                TPowersBigMult[i-2].b[j] <== TPowersBits[i-1][j];
                TPowersBigMult[i-2].p[j] <== order[j];
            }
            for (var j=0; j < k; j++) {
                TPowersBits[i][j] <== TPowersBigMult[i-2].out[j];
            }
        }
    }

    // Compute s^-1 mod n for each signature
    component sinv_range_checks[b][k];
    component sinv_check[b];
    for (var batch_idx = 0; batch_idx < b; batch_idx++) {
        sinv_comp[batch_idx] = mod_inv(n, k, s[batch_idx], order); // circom-pairing/bigint_func.circom
        for (var reg_idx = 0; reg_idx < k; reg_idx++) {
            sinv[batch_idx][reg_idx] <-- sinv_comp[batch_idx][reg_idx];
            sinv_range_checks[batch_idx][reg_idx] = Num2Bits(n);
            sinv_range_checks[batch_idx][reg_idx].in <== sinv[batch_idx][reg_idx];
        }

        sinv_check[batch_idx] = BigMultModP(n, k);
        for (var reg_idx = 0; reg_idx < k; reg_idx++) {
            sinv_check[batch_idx].a[reg_idx] <== sinv[batch_idx][reg_idx];
            sinv_check[batch_idx].b[reg_idx] <== s[batch_idx][reg_idx];
            sinv_check[batch_idx].p[reg_idx] <== order[reg_idx];
        }

        for (var reg_idx = 0; reg_idx < k; reg_idx++) {
            if (reg_idx > 0) {
                sinv_check[batch_idx].out[reg_idx] === 0;
            }
            if (reg_idx == 0) {
                sinv_check[batch_idx].out[reg_idx] === 1;
            }
        }
    }

    // Compute (h * sinv) mod n for each signature
    component g_coeff1[b];
    for (var batch_idx = 0; batch_idx < b; batch_idx++) {
        g_coeff1[batch_idx] = BigMultModP(n, k);
        for (var reg_idx = 0; reg_idx < k; reg_idx++) {
            g_coeff1[batch_idx].a[reg_idx] <== sinv[batch_idx][reg_idx];
            g_coeff1[batch_idx].b[reg_idx] <== msghash[batch_idx][reg_idx];
            g_coeff1[batch_idx].p[reg_idx] <== order[reg_idx];
        }
    }

    // Compute t^i (h * sinv) mod n for each signature
    component g_coeff2[b];
    for (var batch_idx = 0; batch_idx < b; batch_idx++) {
        g_coeff2[batch_idx] = BigMultModP(n, k);
        for (var reg_idx = 0; reg_idx < k; reg_idx++) {
            g_coeff2[batch_idx].a[reg_idx] <== g_coeff1[batch_idx].out[reg_idx];
            g_coeff2[batch_idx].b[reg_idx] <== TPowersBits[batch_idx][reg_idx];
            g_coeff2[batch_idx].p[reg_idx] <== order[reg_idx];
        }
    }

    // compute sum_i t^i (h * sinv) mod n
    component g_coeff_sums[b];
    for (var batch_idx = 0; batch_idx < b; batch_idx++) {
        g_coeff_sums[batch_idx] = BigAddModP(n, k); // circom-pairing/bigint.circom
        for (var reg_idx = 0; reg_idx < k; reg_idx++) {
            if (batch_idx == 0) {
                g_coeff_sums[batch_idx].a[reg_idx] <== 0;
            } else {
                g_coeff_sums[batch_idx].a[reg_idx] <== g_coeff_sums[batch_idx-1].out[reg_idx];
            }
            g_coeff_sums[batch_idx].b[reg_idx] <== g_coeff2[batch_idx].out[reg_idx];
            g_coeff_sums[batch_idx].p[reg_idx] <== order[reg_idx];
        }
    }

    // compute (r * sinv) mod n for each signature
    component pubkey_coeff1[b];
    for (var batch_idx = 0; batch_idx < b; batch_idx++) {
        pubkey_coeff1[batch_idx] = BigMultModP(n, k);
        for (var j = 0; j < k; j++) {
            pubkey_coeff1[batch_idx].a[j] <== sinv[batch_idx][j];
            pubkey_coeff1[batch_idx].b[j] <== r[batch_idx][j];
            pubkey_coeff1[batch_idx].p[j] <== order[j];
        }
    }

    // compute - (r * sinv) mod n for each signature
    component pubkey_coeff2[b];
    for (var i = 0; i < b; i++) {
        pubkey_coeff2[i] = BigSubModP(n, k); // circom-pairing/bigint.circom
        for (var j = 0; j < k; j++) {
            pubkey_coeff2[i].a[j] <== 0;
            pubkey_coeff2[i].b[j] <== pubkey_coeff1[i].out[j];
            pubkey_coeff2[i].p[j] <== order[j];
        }
    }

    // compute t^i (r * sinv) mod n for each signature
    component pubkey_coeff3[b];
    for (var i = 0; i < b; i++) {
        pubkey_coeff3[i] = BigMultModP(n, k);
        for (var j = 0; j < k; j++) {
            pubkey_coeff3[i].a[j] <== pubkey_coeff2[i].out[j];
            pubkey_coeff3[i].b[j] <== TPowersBits[i][j];
            pubkey_coeff3[i].p[j] <== order[j];
        }
    }

    // \sum_i t^i (R_i - (r_i s_i^{-1}) Q_i)
    component linear_combiner = P256LinearCombination(n, k, 2 * b);
    for (var batch_idx = 0; batch_idx < b; batch_idx++) {
        for (var reg_idx = 0; reg_idx < k; reg_idx++) {
            // - t^i * (r_i s_i^{-1}) * Q_i
            linear_combiner.coeffs[batch_idx*2][reg_idx] <== pubkey_coeff3[batch_idx].out[reg_idx];
            linear_combiner.points[batch_idx*2][0][reg_idx] <== pubkey[batch_idx][0][reg_idx];
            linear_combiner.points[batch_idx*2][1][reg_idx] <== pubkey[batch_idx][1][reg_idx];
            // t^i * R_i
            linear_combiner.coeffs[batch_idx*2+1][reg_idx] <== TPowersBits[batch_idx][reg_idx];
            linear_combiner.points[batch_idx*2+1][0][reg_idx] <== r[batch_idx][reg_idx];
            linear_combiner.points[batch_idx*2+1][1][reg_idx] <== rprime[batch_idx][reg_idx];
        }
    }

    // compute (\sum_i t^i (h * sinv)) * G
    component generator_term = ECDSAPrivToPub(n, k); // circom-ecdsa-p256/ecdsa.circom
    for (var j = 0; j < k; j++) {
        generator_term.privkey[j] <== g_coeff_sums[b-1].out[j];
    }

    component compare[2][k];
    signal num_equal[k];
    for (var reg_idx = 0; reg_idx < k; reg_idx++) {
        for (var x_or_y = 0; x_or_y < 2; x_or_y++) {
            compare[x_or_y][reg_idx] = IsEqual();
            compare[x_or_y][reg_idx].in[0] <== linear_combiner.out[x_or_y][reg_idx];
            compare[x_or_y][reg_idx].in[1] <== generator_term.pubkey[x_or_y][reg_idx];
        }
        if (reg_idx == 0) {
            num_equal[0] <== compare[0][reg_idx].out + compare[1][reg_idx].out;
        } else {
            num_equal[reg_idx] <== num_equal[reg_idx-1] + compare[0][reg_idx].out + compare[1][reg_idx].out;
        }
    }
    component SumsEqual = IsZero();
    SumsEqual.in <== num_equal[k-1] - 2*k;
    result <== SumsEqual.out;
}