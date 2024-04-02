pragma circom 2.1.5;

include "./circom-ecdsa-p256/circuits/p256.circom";
include "./circom-ecdsa-p256/circuits/circom-pairing/circuits/curve.circom";

template P256PointOnCurve(n, k){
  signal input x[k];
  signal input y[k];

  var params[4][k] = get_p256_params(); // circom-ecdsa-p256/p256_func.circom

  component poc = PointOnCurve(n, k, params[0], params[1], params[2]); // circom-pairing/curve.circom
  poc.in[0] <== x;
  poc.in[1] <== y;
}

template P256IsEqual(n, k) {
    signal input a[2][k];
    signal input b[2][k];
    signal output out;

    component are_registers_equal[2][k];
    component all_registers_equal = IsEqual();

    for (var reg_idx = 0; reg_idx < k; reg_idx++) {
        for (var x_or_y = 0; x_or_y < 2; x_or_y++) {
            are_registers_equal[x_or_y][reg_idx] = IsEqual();
            are_registers_equal[x_or_y][reg_idx].in[0] <== a[x_or_y][reg_idx];
            are_registers_equal[x_or_y][reg_idx].in[1] <== b[x_or_y][reg_idx];
        }
    }

    signal acc[2*k];
    acc[0] <== are_registers_equal[0][0].out;
    acc[1] <== acc[0] + are_registers_equal[0][1].out;
    acc[2] <== acc[1] + are_registers_equal[0][2].out;
    acc[3] <== acc[2] + are_registers_equal[0][3].out;
    acc[4] <== acc[3] + are_registers_equal[0][4].out;
    acc[5] <== acc[4] + are_registers_equal[0][5].out;
    acc[6] <== acc[5] + are_registers_equal[1][0].out;
    acc[7] <== acc[6] + are_registers_equal[1][1].out;
    acc[8] <== acc[7] + are_registers_equal[1][2].out;
    acc[9] <== acc[8] + are_registers_equal[1][3].out;
    acc[10] <== acc[9] + are_registers_equal[1][4].out;
    acc[11] <== acc[10] + are_registers_equal[1][5].out;

    all_registers_equal.in[0] <== acc[2*k-1];
    all_registers_equal.in[1] <== 2 * k;
    out <== all_registers_equal.out;
}

/* Doubles an elliptic curve point w times */
template P256DoubleRepeat(n, k, w) {
    signal input in[2][k];
    signal output out[2][k];
    component doubler[w];

    doubler[0] = P256Double(n, k); // circom-ecdsa-p256/p256.circom
    for (var j = 0; j < k; j++) {
        doubler[0].in[0][j] <== in[0][j];
        doubler[0].in[1][j] <== in[1][j];
    }


    component point_on_curve[w];
    for (var i = 1; i < w; i++) {
        doubler[i] = P256Double(n, k);
        point_on_curve[i] = P256PointOnCurve(n, k);
        for(var j = 0; j < k; j++){
            point_on_curve[i].x[j] <== doubler[i-1].out[0][j];
            point_on_curve[i].y[j] <== doubler[i-1].out[1][j];
        }
        for (var j = 0; j < k; j++) {
            doubler[i].in[0][j] <== doubler[i-1].out[0][j];
            doubler[i].in[1][j] <== doubler[i-1].out[1][j];
        }
    }

    for (var j = 0; j < k; j++) {
        out[0][j] <== doubler[w-1].out[0][j];
        out[1][j] <== doubler[w-1].out[1][j];
    }
}