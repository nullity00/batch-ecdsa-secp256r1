import fs from "fs";
import { generate_sig } from "./utils";

// This is a hack to make BigInt serializable to JSON
// https://github.com/GoogleChromeLabs/jsbi/issues/30#issuecomment-1006086291
(BigInt.prototype as any).toJSON = function () {
  return this.toString();
};

const main = () => {
  var batch_sizes = [1, 2, 4, 8, 16, 32, 64, 128];
  for (var i = 0; i < batch_sizes.length; i++) {
    const out = generate_sig(batch_sizes[i]);
    fs.writeFileSync(
      `scripts/output/input_${batch_sizes[i]}.json`,
      JSON.stringify(out as any)
    );
  }
};

main();
