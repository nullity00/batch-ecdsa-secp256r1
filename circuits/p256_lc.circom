pragma circom 2.1.5;

include "./circom-ecdsa-p256/circuits/circom-pairing/circuits/bigint_func.circom";
include "p256_ops.circom";

/* Computes a linear combination of ECC points
 * coeffs[b][k] an array of coefficients for the linear combination
 * points[b][2][k] an array of ECC points
 * out[2][k] the computed linear combination of points weighted by coeffs
 * Note: It is expected that none of the points are equal
*/
template P256LinearCombination(n, k, b) {
    // Input & Output Signals
    signal input coeffs[b][k];
    signal input points[b][2][k];
    signal output out[2][k];

    // Variables
    var w = 4;
    var window_size = 1 << w;
    var num_coordinates = div_ceil(n * k, w); // circom-pairing/bigint_func.circom
    var order[100] = get_p256_order(n, k); // circom-ecdsa-p256/p256_func.circom
    var dummyHolder[2][100] = get_dummy_point(n, k); // circom-ecdsa-p256/p256_func.circom
    var dummy[2][k];
    for (var i = 0; i < k; i++) dummy[0][i] = dummyHolder[0][i];
    for (var i = 0; i < k; i++) dummy[1][i] = dummyHolder[1][i];

    // @TODO: Find dummy point for P256
    var dummy2[2][k];
    dummy2[0][0] = 7302857710491818226;
    dummy2[0][1] = 13090816099812022951;
    dummy2[0][2] = 9346046874093976485;
    dummy2[0][3] = 16390367348011359441;
    dummy2[0][4] = 0;
    dummy2[0][5] = 0;

    dummy2[1][0] = 3244438850366025804;
    dummy2[1][1] = 9434351362574893148;
    dummy2[1][2] = 7254847369327388665;
    dummy2[1][3] = 7867482507585870065;
    dummy2[1][4] = 0;
    dummy2[1][5] = 0;

    // Generating lookup table for points[0], ..., points[b-1] between multiples 0 and 2^w-1
    signal lookup_table[b][window_size][2][k];
    component table_doublers[b];
    component table_adders[b][window_size-3];
    for (var i = 0; i < b; i++) {
        for (var j = 0; j < window_size; j++) {
            if (j == 2) {
                table_doublers[i] = P256Double(n, k); // circom-ecdsa-p256/p256.circom
                for (var l = 0; l < k; l++) {
                    table_doublers[i].in[0][l] <== points[i][0][l];
                    table_doublers[i].in[1][l] <== points[i][1][l];
                }
            }
            else if (j > 2) {
                table_adders[i][j-3] = P256AddUnequal(n, k); // circom-ecdsa-p256/p256.circom
                for (var l = 0; l < k; l++) {
                    table_adders[i][j-3].a[0][l] <== points[i][0][l];
                    table_adders[i][j-3].a[1][l] <== points[i][1][l];
                    table_adders[i][j-3].b[0][l] <== lookup_table[i][j-1][0][l];
                    table_adders[i][j-3].b[1][l] <== lookup_table[i][j-1][1][l];
                }
            }
            for (var l = 0; l < k; l++) {
                if (j == 0) {
                    lookup_table[i][j][0][l] <== dummy[0][l];
                    lookup_table[i][j][1][l] <== dummy[1][l];
                } else if (j == 1) {
                    lookup_table[i][j][0][l] <== points[i][0][l];
                    lookup_table[i][j][1][l] <== points[i][1][l];
                } else if (j == 2) {
                    lookup_table[i][j][0][l] <== table_doublers[i].out[0][l];
                    lookup_table[i][j][1][l] <== table_doublers[i].out[1][l];
                } else {
                    lookup_table[i][j][0][l] <== table_adders[i][j-3].out[0][l];
                    lookup_table[i][j][1][l] <== table_adders[i][j-3].out[1][l];
                }
            }
        }
    }

    // Convert each coefficient to a bit representation
    component n2b[b][k];
    for (var batch_idx = 0; batch_idx < b; batch_idx++) {
        for (var reg_idx = 0; reg_idx < k; reg_idx++) {
            n2b[batch_idx][reg_idx] = Num2Bits(n);
            n2b[batch_idx][reg_idx].in <== coeffs[batch_idx][reg_idx];
        }
    }

    // Compute coordinates of each coefficient in base 2^w
    component selectors[b][num_coordinates];
    for (var i = 0; i < b; i++) {
        for (var j = 0; j < num_coordinates; j++) {
            selectors[i][j] = Bits2Num(w);
            for (var l = 0; l < w; l++) {
                var bit_idx1 = (j * w + l) \ n;
                var bit_idx2 = (j * w + l) % n;
                if (bit_idx1 < k) {
                    selectors[i][j].in[l] <== n2b[i][bit_idx1].out[bit_idx2];
                } else {
                    selectors[i][j].in[l] <== 0;
                }
            }
        }
    }

    // Select precomputed elliptic curve points from table using selector coordinates
    component multiplexers[b][num_coordinates][2];
    for (var batch_idx = 0; batch_idx < b; batch_idx++) {
        for (var coord_idx = 0; coord_idx < num_coordinates; coord_idx++) {
            for (var x_or_y = 0; x_or_y < 2; x_or_y++) {
                multiplexers[batch_idx][coord_idx][x_or_y] = Multiplexer(k, window_size);
                multiplexers[batch_idx][coord_idx][x_or_y].sel <== selectors[batch_idx][coord_idx].out;
                for (var reg_idx = 0; reg_idx < k; reg_idx++) {
                    for (var win_idx = 0; win_idx < window_size; win_idx++) {
                        multiplexers[batch_idx][coord_idx][x_or_y].inp[win_idx][reg_idx]
                            <== lookup_table[batch_idx][win_idx][x_or_y][reg_idx];
                    }
                }
            }
        }
    }

    // Keep track of which selectors were zero
    component iszero[b][num_coordinates];
    component has_prev_nonzero[b][num_coordinates];
    for (var batch_idx = 0; batch_idx < b; batch_idx++) {
        for (var coord_idx = 0; coord_idx < num_coordinates; coord_idx++) {
            iszero[batch_idx][coord_idx] = IsZero();
            iszero[batch_idx][coord_idx].in <== selectors[batch_idx][coord_idx].out;
        }
    }
    for (var coord_idx = 0; coord_idx < num_coordinates; coord_idx++) {
        has_prev_nonzero[0][coord_idx] = OR();
        has_prev_nonzero[0][coord_idx].a <== 0;
        has_prev_nonzero[0][coord_idx].b <== 1 - iszero[0][coord_idx].out;
    }
    for (var coord_idx = 0; coord_idx < num_coordinates; coord_idx++) {
        for (var batch_idx = 1; batch_idx < b; batch_idx++) {
            has_prev_nonzero[batch_idx][coord_idx] = OR();
            has_prev_nonzero[batch_idx][coord_idx].a <== has_prev_nonzero[batch_idx-1][coord_idx].out;
            has_prev_nonzero[batch_idx][coord_idx].b <== 1 - iszero[batch_idx][coord_idx].out;
        }
    }

    // keeps track of whether the whole next coordinate has a 0 or not
    component has_prev_coordinate_nonzero[num_coordinates];
    for (var coord_idx = num_coordinates - 1; coord_idx >= 0; coord_idx--) {
        has_prev_coordinate_nonzero[coord_idx] = OR();
        if (coord_idx == num_coordinates - 1) {
            // This is just 0, since there is no previous entry
            has_prev_coordinate_nonzero[coord_idx].a <== 0;
            has_prev_coordinate_nonzero[coord_idx].b <== 0;
        } else {
            // Either there was a column in the past with a 1 or the previous column was 1
            has_prev_coordinate_nonzero[coord_idx].a <== has_prev_coordinate_nonzero[coord_idx+1].out;
            has_prev_coordinate_nonzero[coord_idx].b <== has_prev_nonzero[b-1][coord_idx+1].out;
        }
    }

    // Efficient computation of linear combinations of elliptic curve points
    signal acc[num_coordinates][2][k];
    signal intermed1[num_coordinates][b-1][2][k];
    signal intermed2[num_coordinates][b-1][2][k];
    signal intermed3[num_coordinates][2][k];
    signal intermed4[num_coordinates][2][k];
    signal partial[num_coordinates][b][2][k];
    component doublers[num_coordinates];
    component adders[num_coordinates][b-1];
    component are_points_equal[num_coordinates][b-1];
    component final_adder[num_coordinates-1];

    for (var coord_idx = num_coordinates - 1; coord_idx >= 0; coord_idx--) {
        // If this is not the first coordinate, double the accumulator from the last iteration
        if (coord_idx != num_coordinates - 1) {
            doublers[coord_idx] = P256DoubleRepeat(n, k, w); 
            for (var reg_idx = 0; reg_idx < k; reg_idx++) {
                for (var x_or_y = 0; x_or_y < 2; x_or_y++) {
                    doublers[coord_idx].in[x_or_y][reg_idx] <== acc[coord_idx+1][x_or_y][reg_idx];
                }
            }
        }

        // Set the first index of the partial sum to the multiplexer output (could be dummy!)
        for (var reg_idx = 0; reg_idx < k; reg_idx++) {
            for (var x_or_y = 0; x_or_y < 2; x_or_y++) {
                partial[coord_idx][0][x_or_y][reg_idx] <== multiplexers[0][coord_idx][x_or_y].out[reg_idx];
            }
        }

        // Compute the remaining partial sums
        for (var batch_idx = 1; batch_idx < b; batch_idx++) {
            are_points_equal[coord_idx][batch_idx-1] = P256IsEqual(n, k);
            for (var reg_idx = 0; reg_idx < k; reg_idx++) {
                for (var x_or_y = 0; x_or_y < 2; x_or_y++) {
                    are_points_equal[coord_idx][batch_idx-1].a[x_or_y][reg_idx] <==
                        partial[coord_idx][batch_idx-1][x_or_y][reg_idx];
                    are_points_equal[coord_idx][batch_idx-1].b[x_or_y][reg_idx] <==
                        multiplexers[batch_idx][coord_idx][x_or_y].out[reg_idx];
                }
            }

            // Compute the prev partial sum + current multiplexer output (note: not always used)
            adders[coord_idx][batch_idx-1] = P256AddUnequal(n, k); // p256.circom
            for (var reg_idx = 0; reg_idx < k; reg_idx++) {
                for (var x_or_y = 0; x_or_y < 2; x_or_y++) {
                    adders[coord_idx][batch_idx-1].a[x_or_y][reg_idx] <==
                        are_points_equal[coord_idx][batch_idx-1].out * (dummy2[x_or_y][reg_idx] - partial[coord_idx][batch_idx-1][x_or_y][reg_idx])
                        + partial[coord_idx][batch_idx-1][x_or_y][reg_idx];
                    adders[coord_idx][batch_idx-1].b[x_or_y][reg_idx] <==
                        multiplexers[batch_idx][coord_idx][x_or_y].out[reg_idx];
                }
            }

            // Compute new partial sum according to various cases to handle dummy point
            for (var reg_idx = 0; reg_idx < k; reg_idx++) {
                for (var x_or_y = 0; x_or_y < 2; x_or_y++) {
                    // Case 1: there was a prev non-zero selector
                    intermed1[coord_idx][batch_idx-1][x_or_y][reg_idx] <==
                        iszero[batch_idx][coord_idx].out * (partial[coord_idx][batch_idx-1][x_or_y][reg_idx] - adders[coord_idx][batch_idx-1].out[x_or_y][reg_idx])
                        + adders[coord_idx][batch_idx-1].out[x_or_y][reg_idx];


                    // IF THERE WAS NO PREV NON ZERO SELECTOR => partial = 0
                    // IF THERE WAS NO PREV NON ZERO SELECTOR => partial = dummy
                    // Case 2: there is not prev non-zero selector
                    intermed2[coord_idx][batch_idx-1][x_or_y][reg_idx] <==
                        iszero[batch_idx][coord_idx].out * (dummy[x_or_y][reg_idx] - multiplexers[batch_idx][coord_idx][x_or_y].out[reg_idx])
                        + multiplexers[batch_idx][coord_idx][x_or_y].out[reg_idx];
                    // If there was prev non-zero selector, set partial to intermed1. otherwise, intermed2
                    partial[coord_idx][batch_idx][x_or_y][reg_idx] <==
                        has_prev_nonzero[batch_idx-1][coord_idx].out
                        * (intermed1[coord_idx][batch_idx-1][x_or_y][reg_idx] - intermed2[coord_idx][batch_idx-1][x_or_y][reg_idx])
                        + intermed2[coord_idx][batch_idx-1][x_or_y][reg_idx];
                }
            }
        }

        // If this is the first round, set the accumulator to the partial sum
        // We do not check has_prev_coordinate_nonzero
        if (coord_idx == num_coordinates - 1) {
            for (var reg_idx = 0; reg_idx < k; reg_idx++) {
                for (var x_or_y = 0; x_or_y < 2; x_or_y++) {
                    acc[coord_idx][x_or_y][reg_idx] <==
                        (1 - has_prev_nonzero[b-1][coord_idx].out) * (dummy[x_or_y][reg_idx] - partial[coord_idx][b-1][x_or_y][reg_idx])
                        + partial[coord_idx][b-1][x_or_y][reg_idx];
                }
            }
        } else {
            final_adder[coord_idx] = P256AddUnequal(n, k);
            for (var reg_idx = 0; reg_idx < k; reg_idx++) {
                for (var x_or_y = 0; x_or_y < 2; x_or_y++) {
                    final_adder[coord_idx].a[x_or_y][reg_idx] <== doublers[coord_idx].out[x_or_y][reg_idx];
                    final_adder[coord_idx].b[x_or_y][reg_idx] <== partial[coord_idx][b-1][x_or_y][reg_idx];
                }
            }

            for (var reg_idx = 0; reg_idx < k; reg_idx++) {
                for (var x_or_y = 0; x_or_y < 2; x_or_y++) {
                    /*
                    Case 1: has_prev_coordinate_nonzero[coord_idx] = 1, has_prev_nonzero[b-1][coord_idx] = 1
                    acc = final_addr = doublers + partial (result from the past + current result)
                    Case 2: has_prev_coordinate_nonzero[coord_idx] = 1, has_prev_nonzero[b-1][coord_idx] = 0
                    acc = doublers (result from the past)
                    Case 3:  has_prev_coordinate_nonzero[coord_idx] = 0, has_prev_nonzero[b-1][coord_idx] = 0
                    acc = dummy_point
                    Case 4: has_prev_coordinate_nonzero[coord_idx] = 0, has_prev_nonzero[b-1][coord_idx] = 1
                    acc = partial (current result)
                    */
                    intermed3[coord_idx][x_or_y][reg_idx] <== has_prev_nonzero[b-1][coord_idx].out * (final_adder[coord_idx].out[x_or_y][reg_idx] - doublers[coord_idx].out[x_or_y][reg_idx])
                        + doublers[coord_idx].out[x_or_y][reg_idx];
                    intermed4[coord_idx][x_or_y][reg_idx] <== (1-has_prev_nonzero[b-1][coord_idx].out) * (dummy[x_or_y][reg_idx])
                        + (has_prev_nonzero[b-1][coord_idx].out) * (partial[coord_idx][b-1][x_or_y][reg_idx]);

                    acc[coord_idx][x_or_y][reg_idx] <== has_prev_coordinate_nonzero[coord_idx].out * (intermed3[coord_idx][x_or_y][reg_idx] - intermed4[coord_idx][x_or_y][reg_idx])
                        + intermed4[coord_idx][x_or_y][reg_idx];
                }
            }
        }
    }

    // Write result to output elliptic curve point signal
    for (var reg_idx = 0; reg_idx < k; reg_idx++) {
        for (var x_or_y = 0; x_or_y < 2; x_or_y++) {
            out[x_or_y][reg_idx] <== acc[0][x_or_y][reg_idx];
        }
    }
}