import {
  expExampleBls12381KeyPair,
  expExampleBls12381KeyPair2,
  expVCDocument,
  expVCDocument2,
  expRevealDocument,
  expRevealDocument2,
  customLoader
} from "./__fixtures__";

import {
  BbsBlsSignature2020,
  BbsBlsSignatureProof2020,
  BbsBlsSignatureProofTermwise2020,
  BbsBlsSignatureTermwise2020,
  Bls12381G2KeyPair
} from "../src/index";
import { signDeriveVerify, signDeriveVerifyMulti } from "./utils";

const expKey1 = new Bls12381G2KeyPair(expExampleBls12381KeyPair);
const expKey2 = new Bls12381G2KeyPair(expExampleBls12381KeyPair2);

describe("experimental verifiable credentials", () => {
  it("[StringStatement] should sign, derive proof, and verify proof on experimental verifiable credential", async () => {
    const vc = { ...expVCDocument };
    await signDeriveVerify(
      vc,
      expRevealDocument,
      {},
      expKey1,
      customLoader,
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
      expKey1,
      customLoader,
      BbsBlsSignatureTermwise2020,
      BbsBlsSignatureProofTermwise2020
    );
  });

  it("[TermwiseStatement] should sign multiple VCs, derive a proof from them, and verify the proof", async () => {
    const vc = { ...expVCDocument };
    const vc2 = { ...expVCDocument2 };
    await signDeriveVerifyMulti(
      [
        [vc, expRevealDocument, expKey1],
        [vc2, expRevealDocument2, expKey2]
      ],
      customLoader,
      BbsBlsSignatureTermwise2020,
      BbsBlsSignatureProofTermwise2020
    );
  });
});
