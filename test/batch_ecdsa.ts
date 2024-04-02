import path from "path";
import { p256 } from "@noble/curves/p256";
import { expect, assert } from 'chai';
import _ from 'lodash';
import { generate_sig, bigint_to_array, uint8Array_to_bigint, bigint_to_uint8Array, mod, invert } from "../scripts/utils";

const circom_tester = require('circom_tester');
const wasm_tester = circom_tester.wasm;

const _0n = BigInt(0);
const _1n = BigInt(1);
const _2n = BigInt(2);
const _3n = BigInt(3);
const _8n = BigInt(8);

describe('ECDSABatchVerifyNoPubkeyCheck', function () {
  this.timeout(1000 * 1000);

  let circuit: any;
  before(async function () {
    circuit = await wasm_tester(path.join(__dirname, 'circuits', 'test_batch_ecdsa_verify_4.circom'));
  });

  var test_batch_ecdsa_verify = function () {
    
      it('testing correct sig', async function () {
        var x = await generate_sig(4);
        var res = 1n;
        let witness = await circuit.calculateWitness({
          r: x.r,
          rprime: x.rprime,
          s: x.s,
          msghash: x.msghash,
          pubkey: x.pubkey,
        });
        expect(witness[1]).to.equal(res);
        await circuit.checkConstraints(witness);
      });

      it('testing incorrect sig', async function () {
        var x = await generate_sig(4);
        var res = 0n;
        let witness = await circuit.calculateWitness({
          r: x.r,
          rprime: x.rprime,
          s: x.s,
          msghash: x.msghash.map((x: bigint) => x + _1n),
          pubkey: x.pubkey,
        });
        expect(witness[1]).to.equal(res);
        await circuit.checkConstraints(witness);
      });
  };

  test_batch_ecdsa_verify();
});