import { p256 } from "@noble/curves/p256";
import { SignatureType } from "@noble/curves/abstract/weierstrass";
import crypto from "crypto";
import fs from "fs";

// This is a hack to make BigInt serializable to JSON
// https://github.com/GoogleChromeLabs/jsbi/issues/30#issuecomment-1006086291
(BigInt.prototype as any).toJSON = function () {
  return this.toString();
};

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

const generate_sig = (numSignatures: number) => {
  /*
   * This is a script for generating sample signatures for the sig_ecdsa circuits.
   * Useful for generating batches of random signatures when needed.
   */
  const inputs: any = {
    r: [],
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
    const r_array = bigint_to_array(43, 6, r);
    const s_array = bigint_to_array(43, 6, s);
    const pub0array = bigint_to_array(43, 6, pubKey.x);
    const pub1array = bigint_to_array(43, 6, pubKey.y);
    const msgArray = bigint_to_array(43, 6, BigInt("0x" + msg.toString("hex")));

    inputs.r.push(r_array);
    inputs.s.push(s_array);
    inputs.msghash.push(msgArray);
    inputs.pubkey.push([pub0array, pub1array]);
  }

  fs.writeFileSync(
    `scripts/output/input_${numSignatures}.json`,
    JSON.stringify(inputs as any)
  );
};

const main = () => {
  var batch_sizes = [1, 2, 4, 8, 16, 32, 64, 128];
  for (var i = 0; i < batch_sizes.length; i++) {
    generate_sig(batch_sizes[i]);
  }
};

main();
