import {
  expExampleBls12381KeyPair,
  expVCDocument,
  expRevealDocument,
  expCustomLoader
} from "./__fixtures__";

import { Bls12381G2KeyPair } from "../src/index";
import { signDeriveVerify } from "./utils";

const expKey = new Bls12381G2KeyPair(expExampleBls12381KeyPair);

describe("experimental verifiable credentials", () => {
  it("should sign, derive proof, and verify proof on experimental verifiable credential", async () => {
    await signDeriveVerify(
      expVCDocument,
      expRevealDocument,
      {},
      expKey,
      expCustomLoader
    );
  });
});
