import { p256 } from "@noble/curves/p256";
import { SignatureType } from "@noble/curves/abstract/weierstrass";
import crypto from "crypto";

function bigint_to_array(n: number, k: number, x: bigint) {
  let mod: bigint = 1n;
  for (var idx = 0; idx < n; idx++) {
    mod = mod * 2n;
  }

  let ret: bigint[] = [];
  var x_temp: bigint = x;
  for (var idx = 0; idx < k; idx++) {
    ret.push(x_temp % mod);
    x_temp = x_temp / mod;
  }
  return ret;
}

// Mod n operators from @noble-p256
const _0n = BigInt(0);
const _1n = BigInt(1);

function mod(a: bigint, b: bigint = p256.CURVE.p): bigint {
  const result = a % b;
  return result >= _0n ? result : b + result;
}

// Inverses number over modulo
function invert(number: bigint, modulo: bigint = p256.CURVE.p): bigint {
  if (number === _0n || modulo <= _0n) {
    throw new Error(
      `invert: expected positive integers, got n=${number} mod=${modulo}`
    );
  }
  // Eucledian GCD https://brilliant.org/wiki/extended-euclidean-algorithm/
  let a = mod(number, modulo);
  let b = modulo;
  // prettier-ignore
  let x = _0n, y = _1n, u = _1n, v = _0n;
  while (a !== _0n) {
    const q = b / a;
    const r = b % a;
    const m = x - u * q;
    const n = y - v * q;
    // prettier-ignore
    b = a, a = r, x = u, y = v, u = m, v = n;
  }
  const gcd = b;
  if (gcd !== _1n) throw new Error("invert: does not exist");
  return mod(x, modulo);
}

function uint8Array_to_bigint(x: Uint8Array) {
  var ret: bigint = 0n;
  for (var idx = 0; idx < x.length; idx++) {
    ret = ret * 256n;
    ret = ret + BigInt(x[idx]);
  }
  return ret;
}

const n = p256.CURVE.n;

const generate_sig = (numSignatures: number) => {
  /*
   * This is a script for generating sample signatures for the sig_ecdsa circuits.
   * Useful for generating batches of random signatures when needed.
   */
  const inputs: any = {
    r: [],
    rprime: [],
    s: [],
    msghash: [],
    pubkey: [],
  };

  for (let i = 0; i < numSignatures; i++) {
    const privKey = p256.utils.randomPrivateKey();
    const pubKey = p256.ProjectivePoint.fromPrivateKey(privKey);
    const msg = crypto.randomBytes(32);

    const sig: SignatureType = p256.sign(msg, privKey);
    const r: bigint = sig.r;
    const s: bigint = sig.s;

    // computing v = r_i' in R_i = (r_i, r_i')
    var p_1 = p256.ProjectivePoint.BASE.multiply(
      mod(uint8Array_to_bigint(msg) * invert(s, n), n)
    );
    var p_2 = p256.ProjectivePoint.fromPrivateKey(privKey).multiply(
      mod(r * invert(s, n), n)
    );
    var p_res = p_1.add(p_2);
    var rprime: bigint = p_res.y;

    const r_array = bigint_to_array(43, 6, r);
    const rprime_array: bigint[] = bigint_to_array(43, 6, rprime);
    const s_array = bigint_to_array(43, 6, s);
    const pub0array = bigint_to_array(43, 6, pubKey.x);
    const pub1array = bigint_to_array(43, 6, pubKey.y);
    const msgArray = bigint_to_array(43, 6, BigInt("0x" + msg.toString("hex")));

    inputs.r.push(r_array);
    inputs.rprime.push(rprime_array);
    inputs.s.push(s_array);
    inputs.msghash.push(msgArray);
    inputs.pubkey.push([pub0array, pub1array]);
  }

  return inputs;
};

// bigendian
function bigint_to_uint8Array(x: bigint) {
  var ret: Uint8Array = new Uint8Array(32);
  for (var idx = 31; idx >= 0; idx--) {
    ret[idx] = Number(x % 256n);
    x = x / 256n;
  }
  return ret;
}

export { bigint_to_array, mod, invert, uint8Array_to_bigint, generate_sig, bigint_to_uint8Array };
