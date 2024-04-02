import path from "path";
import { expect } from "chai";
import _ from "lodash";
import { generate_sig } from "../scripts/utils";

const circom_tester = require("circom_tester");
const wasm_tester = circom_tester.wasm;

const randomMsgHash = [
  [
    378014510781, 2635680598305, 1122110594975, 5768456357407, 8223520554262,
    1821163896477,
  ],
  [
    190242646973, 3351673368361, 4147977096671, 6968815966824, 4023907958308,
    2160301479018,
  ],
];

describe("P256BatchECDSAVerifyNoPubkeyCheck", () => {
  // this.timeout(1000 * 1000);

  let circuit: any;
  var x = generate_sig(2);
  before(async function () {
    circuit = await wasm_tester(
      path.join(__dirname, "circuits", "test_batch_ecdsa_verify_2.circom")
    );
  });

  var test_batch_ecdsa_verify = function () {
    it("testing correct sig", async function () {
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

    it("testing incorrect sig", async function () {
      var res = 0n;
      let witness = await circuit.calculateWitness({
        r: x.r,
        rprime: x.rprime,
        s: x.s,
        msghash: randomMsgHash,
        pubkey: x.pubkey,
      });
      expect(witness[1]).to.equal(res);
      await circuit.checkConstraints(witness);
    });
  };

  test_batch_ecdsa_verify();
});
