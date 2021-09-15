import {
  expExampleBls12381KeyPair,
  expExampleBls12381KeyPair2,
  expExampleBls12381KeyPair3,
  expVCDocument,
  expVCDocument2,
  expVCDocument3,
  expRevealDocument,
  expRevealDocument2,
  expRevealDocument3,
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
const expKey3 = new Bls12381G2KeyPair(expExampleBls12381KeyPair3);

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
    const vc3 = { ...expVCDocument3 };
    const hiddenUris = [
      "http://example.org/credentials/1234",
      "http://example.org/credentials/9876",
      "http://example.org/credentials/abcd",
      "dummy",
      "dummy",
      "did:example:holder1",
      "did:example:cityA"
    ];

    await signDeriveVerifyMulti(
      [
        { vc, revealDocument: expRevealDocument, key: expKey1 },
        { vc: vc2, revealDocument: expRevealDocument2, key: expKey2 },
        { vc: vc3, revealDocument: expRevealDocument3, key: expKey3 }
      ],
      hiddenUris,
      customLoader,
      BbsBlsSignatureTermwise2020,
      BbsBlsSignatureProofTermwise2020
    );
  });

  it("[TermwiseStatement] should sign single VC, derive a proof from it, and verify the proof", async () => {
    const vc = { ...expVCDocument };
    const hiddenUris = [
      "http://example.org/credentials/1234",
      "http://example.org/credentials/9876",
      "http://example.org/credentials/abcd",
      "dummy",
      "dummy",
      "did:example:holder1",
      "did:example:cityA"
    ];

    await signDeriveVerifyMulti(
      [{ vc, revealDocument: expRevealDocument, key: expKey1 }],
      hiddenUris,
      customLoader,
      BbsBlsSignatureTermwise2020,
      BbsBlsSignatureProofTermwise2020
    );
  });
});
