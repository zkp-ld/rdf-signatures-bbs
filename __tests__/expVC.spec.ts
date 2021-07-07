import {
  expExampleBls12381KeyPair,
  expVCDocument,
  expRevealDocument,
  expCustomLoader
} from "./__fixtures__";

import {
  BbsBlsSignature2020,
  BbsBlsSignatureProof2020,
  BbsBlsSignatureProofTermwise2020,
  BbsBlsSignatureTermwise2020,
  Bls12381G2KeyPair
} from "../src/index";
import { signDeriveVerify } from "./utils";

const expKey = new Bls12381G2KeyPair(expExampleBls12381KeyPair);

describe("experimental verifiable credentials", () => {
  it("[StringStatement] should sign, derive proof, and verify proof on experimental verifiable credential", async () => {
    const vc = { ...expVCDocument };
    await signDeriveVerify(
      vc,
      expRevealDocument,
      {},
      expKey,
      expCustomLoader,
      BbsBlsSignature2020,
      BbsBlsSignatureProof2020
    );
  });

  it("[TermwiseStatement] should sign, derive proof, and verify proof on experimental verifiable credential", async () => {
    const vc = { ...expVCDocument };
    await signDeriveVerify(
      vc,
      expRevealDocument,
      {},
      expKey,
      expCustomLoader,
      BbsBlsSignatureTermwise2020,
      BbsBlsSignatureProofTermwise2020
    );
  });
});
