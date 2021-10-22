import {
  exampleBls12381KeyPair,
  customLoader,
  testAnonymousVcDocument,
  testRevealAnonymousVcDocument,
  testNestedRevealDocument,
  testNestedRevealFullDocument,
  testNestedAnonymousVcDocument,
  testAnonymousVcComplexDocument,
  testRevealAnonymousVcComplexDocument
} from "./__fixtures__";
import {
  Bls12381G2KeyPair,
  BbsTermwiseSignature2021,
  BbsTermwiseSignatureProof2021
} from "../src/index";
import {
  signDeriveVerify,
  signDeriveVerifyMulti,
  signDeriveVerifyMultiJSigLike
} from "./utils";

const key = new Bls12381G2KeyPair(exampleBls12381KeyPair);

describe("BbsTermwiseSignature2021 and BbsTermwiseSignatureProof2021", () => {
  it("should sign, derive proof, and verify proof on anonymous verifiable credential", async () => {
    const vc = { ...testAnonymousVcDocument };
    const hiddenUris: any[] = ["did:example:489398593"];

    await signDeriveVerifyMulti(
      [{ vc, revealDocument: testRevealAnonymousVcDocument, key }],
      hiddenUris,
      customLoader,
      BbsTermwiseSignature2021,
      BbsTermwiseSignatureProof2021
    );
  });

  it("should sign, derive proof, and verify proof on anonymous verifiable credential using jsonld-signatures-like APIs", async () => {
    const vc = { ...testAnonymousVcDocument };
    const hiddenUris: any[] = ["did:example:489398593"];

    await signDeriveVerifyMultiJSigLike(
      [{ vc, revealDocument: testRevealAnonymousVcDocument, key }],
      hiddenUris,
      customLoader,
      BbsTermwiseSignature2021,
      BbsTermwiseSignatureProof2021
    );
  });

  it("should sign, derive proof, and verify proof on anonymous nested and partially revealed verifiable credential", async () => {
    const vc = { ...testNestedAnonymousVcDocument };
    const hiddenUris: any[] = ["did:example:489398593"];

    await signDeriveVerifyMulti(
      [{ vc, revealDocument: testNestedRevealDocument, key }],
      hiddenUris,
      customLoader,
      BbsTermwiseSignature2021,
      BbsTermwiseSignatureProof2021
    );
  });

  it("should sign, derive proof, and verify proof on anonymous nested and partially revealed verifiable credential using jsonld-signatures-like APIs", async () => {
    const vc = { ...testNestedAnonymousVcDocument };
    const hiddenUris: any[] = ["did:example:489398593"];

    await signDeriveVerifyMultiJSigLike(
      [{ vc, revealDocument: testNestedRevealDocument, key }],
      hiddenUris,
      customLoader,
      BbsTermwiseSignature2021,
      BbsTermwiseSignatureProof2021
    );
  });

  it("should sign, derive proof, and verify proof on anonymous nested and fully revealed verifiable credential", async () => {
    const vc = { ...testNestedAnonymousVcDocument };
    const hiddenUris: any[] = ["did:example:489398593"];

    await signDeriveVerifyMulti(
      [{ vc, revealDocument: testNestedRevealFullDocument, key }],
      hiddenUris,
      customLoader,
      BbsTermwiseSignature2021,
      BbsTermwiseSignatureProof2021
    );
  });

  it("should sign, derive proof, and verify proof on anonymous nested and fully revealed verifiable credential using jsonld-signatures-like APIs", async () => {
    const vc = { ...testNestedAnonymousVcDocument };
    const hiddenUris: any[] = ["did:example:489398593"];

    await signDeriveVerifyMultiJSigLike(
      [{ vc, revealDocument: testNestedRevealFullDocument, key }],
      hiddenUris,
      customLoader,
      BbsTermwiseSignature2021,
      BbsTermwiseSignatureProof2021
    );
  });

  it("should sign, derive proof, and verify proof on anonymous nested complex and partially revealed verifiable credential", async () => {
    await signDeriveVerify(
      testAnonymousVcComplexDocument,
      testRevealAnonymousVcComplexDocument,
      key,
      customLoader,
      BbsTermwiseSignature2021,
      BbsTermwiseSignatureProof2021,
      {
        id: expect.anything(),
        batchNumber: "1183738569",
        type: "VaccinationEvent"
      }
    );
  });
});
