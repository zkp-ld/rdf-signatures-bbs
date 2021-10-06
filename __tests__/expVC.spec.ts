import jsigs from "jsonld-signatures";

import {
  expExampleBls12381KeyPair,
  expExampleBls12381KeyPair2,
  expExampleBls12381KeyPair3,
  expVCDocument,
  expVCDocument2,
  expVCDocument3,
  expVCDocument4,
  expRevealDocument,
  expRevealDocument2,
  expRevealDocument3,
  expRevealDocument4,
  customLoader
} from "./__fixtures__";

import {
  BbsBlsSignature2020,
  BbsBlsSignatureProof2020,
  BbsBlsSignatureProofTermwise2020,
  BbsBlsSignatureTermwise2020,
  Bls12381G2KeyPair,
  verifyProofMulti
} from "../src/index";

import {
  signDeriveMultiJSigLike,
  signDeriveVerify,
  signDeriveVerifyMulti,
  signDeriveVerifyMultiJSigLike
} from "./utils";

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

  it("[TermwiseStatement] (2) should sign single VC, derive a proof from it, and verify the proof", async () => {
    const vc = { ...expVCDocument4 };
    const hiddenUris = [
      "http://example.org/credentials/1234",
      "http://example.org/credentials/9876",
      "http://example.org/credentials/abcd",
      "did:example:holder1",
      "did:example:holder2",
      "did:example:cityA"
    ];

    await signDeriveVerifyMulti(
      [{ vc, revealDocument: expRevealDocument4, key: expKey1 }],
      hiddenUris,
      customLoader,
      BbsBlsSignatureTermwise2020,
      BbsBlsSignatureProofTermwise2020
    );
  });
});

describe("experimental verifiable credentials using JSON-LD-Signatures-like APIs", () => {
  it("should sign multiple VCs, derive a proof from them, and verify the proof", async () => {
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

    await signDeriveVerifyMultiJSigLike(
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

  it("should sign single VC, derive a proof from it, and verify the proof", async () => {
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

    await signDeriveVerifyMultiJSigLike(
      [{ vc, revealDocument: expRevealDocument, key: expKey1 }],
      hiddenUris,
      customLoader,
      BbsBlsSignatureTermwise2020,
      BbsBlsSignatureProofTermwise2020
    );
  });

  it("[TermwiseStatement] (2) should sign single VC, derive a proof from it, and verify the proof", async () => {
    const vc = { ...expVCDocument4 };
    const hiddenUris = [
      "http://example.org/credentials/1234",
      "http://example.org/credentials/9876",
      "http://example.org/credentials/abcd",
      "did:example:holder1",
      "did:example:holder2",
      "did:example:cityA"
    ];

    await signDeriveVerifyMultiJSigLike(
      [{ vc, revealDocument: expRevealDocument4, key: expKey1 }],
      hiddenUris,
      customLoader,
      BbsBlsSignatureTermwise2020,
      BbsBlsSignatureProofTermwise2020
    );
  });

  it("[TermwiseStatement] should verify derived proofs", async () => {
    const vc = { ...expVCDocument };
    const hiddenUris = [
      "http://example.org/credentials/1234",
      "did:example:holder1",
      "did:example:cityA"
    ];

    const derivedProofs = await signDeriveMultiJSigLike(
      [{ vc, revealDocument: expRevealDocument, key: expKey1 }],
      hiddenUris,
      customLoader,
      BbsBlsSignatureTermwise2020,
      BbsBlsSignatureProofTermwise2020
    );

    const result = await verifyProofMulti(derivedProofs, {
      suite: new BbsBlsSignatureProofTermwise2020(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader,
      expansionMap: false
    });
    expect(result.verified).toBeTruthy();
  });

  it("[TermwiseStatement] should not verify derived proofs where credentialSubject.type is edited", async () => {
    const vc = { ...expVCDocument };
    const hiddenUris = [
      "http://example.org/credentials/1234",
      "did:example:holder1",
      "did:example:cityA"
    ];

    const derivedProofs = await signDeriveMultiJSigLike(
      [{ vc, revealDocument: expRevealDocument, key: expKey1 }],
      hiddenUris,
      customLoader,
      BbsBlsSignatureTermwise2020,
      BbsBlsSignatureProofTermwise2020
    );

    let modifiedProofs = [...derivedProofs];
    modifiedProofs[0].credentialSubject.type = "PersonXXX";

    console.log(`
# modified proofs (0):
${JSON.stringify(modifiedProofs, null, 2)}`);

    const result = await verifyProofMulti(modifiedProofs, {
      suite: new BbsBlsSignatureProofTermwise2020(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader,
      expansionMap: false
    });

    console.log(result);
    expect(result.verified).toBeFalsy();
  });

  it("[TermwiseStatement] should not verify derived proofs where anonymized credential.id is edited", async () => {
    const vc = { ...expVCDocument };
    const hiddenUris = [
      "http://example.org/credentials/1234",
      "did:example:holder1",
      "did:example:cityA"
    ];

    const derivedProofs = await signDeriveMultiJSigLike(
      [{ vc, revealDocument: expRevealDocument, key: expKey1 }],
      hiddenUris,
      customLoader,
      BbsBlsSignatureTermwise2020,
      BbsBlsSignatureProofTermwise2020
    );

    let modifiedProofs = [...derivedProofs];
    modifiedProofs[0].id = "urn:anon:999";

    console.log(`
# modified proofs (0):
${JSON.stringify(modifiedProofs, null, 2)}`);

    const result = await verifyProofMulti(modifiedProofs, {
      suite: new BbsBlsSignatureProofTermwise2020(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader,
      expansionMap: false
    });

    console.log(result);
    expect(result.verified).toBeFalsy();
  });

  it("[TermwiseStatement] should not verify derived proofs where anonymized credentialSubject.id is edited", async () => {
    const vc = { ...expVCDocument };
    const hiddenUris = [
      "http://example.org/credentials/1234",
      "did:example:holder1",
      "did:example:cityA"
    ];

    const derivedProofs = await signDeriveMultiJSigLike(
      [{ vc, revealDocument: expRevealDocument, key: expKey1 }],
      hiddenUris,
      customLoader,
      BbsBlsSignatureTermwise2020,
      BbsBlsSignatureProofTermwise2020
    );

    let modifiedProofs = [...derivedProofs];
    modifiedProofs[0].credentialSubject.id = "urn:anon:999";

    console.log(`
# modified proofs (0):
${JSON.stringify(modifiedProofs, null, 2)}`);

    const result = await verifyProofMulti(modifiedProofs, {
      suite: new BbsBlsSignatureProofTermwise2020(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader,
      expansionMap: false
    });

    console.log(result);
    expect(result.verified).toBeFalsy();
  });

  it("[TermwiseStatement] should not verify derived proofs where anonymized credentialSubject.*.id is edited", async () => {
    const vc = { ...expVCDocument };
    const hiddenUris = [
      "http://example.org/credentials/1234",
      "did:example:holder1",
      "did:example:cityA"
    ];

    const derivedProofs = await signDeriveMultiJSigLike(
      [{ vc, revealDocument: expRevealDocument, key: expKey1 }],
      hiddenUris,
      customLoader,
      BbsBlsSignatureTermwise2020,
      BbsBlsSignatureProofTermwise2020
    );

    let modifiedProofs = [...derivedProofs];
    modifiedProofs[0].credentialSubject.homeLocation.id = "urn:anon:999";

    console.log(`
# modified proofs (0):
${JSON.stringify(modifiedProofs, null, 2)}`);

    const result = await verifyProofMulti(modifiedProofs, {
      suite: new BbsBlsSignatureProofTermwise2020(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader,
      expansionMap: false
    });

    console.log(result);
    expect(result.verified).toBeFalsy();
  });

  it("[TermwiseStatement] should not sign VC with invalid context", async () => {
    let vc = { ...expVCDocument };
    vc["@context"] = [...vc["@context"]];
    vc["@context"].push("https://dummy.example.org/");

    const sign = () =>
      jsigs.sign(vc, {
        suite: new BbsBlsSignatureTermwise2020({ key: expKey1 }),
        purpose: new jsigs.purposes.AssertionProofPurpose(),
        documentLoader: customLoader,
        expansionMap: false
      });
    await expect(sign).rejects.toThrow();
  });

  it("[TermwiseStatement] should not be panicked due to Wasm error when modifying proofValue", async () => {
    const vc = { ...expVCDocument };
    const hiddenUris = [
      "http://example.org/credentials/1234",
      "did:example:holder1",
      "did:example:cityA"
    ];

    const derivedProofs = await signDeriveMultiJSigLike(
      [{ vc, revealDocument: expRevealDocument, key: expKey1 }],
      hiddenUris,
      customLoader,
      BbsBlsSignatureTermwise2020,
      BbsBlsSignatureProofTermwise2020
    );

    // remove first byte from proofValue
    let modifiedProofs = [...derivedProofs];
    modifiedProofs[0].proof.proofValue =
      modifiedProofs[0].proof.proofValue.slice(1);

    console.log(`
# modified proofs (0):
${JSON.stringify(modifiedProofs, null, 2)}`);

    const result = await verifyProofMulti(modifiedProofs, {
      suite: new BbsBlsSignatureProofTermwise2020(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader,
      expansionMap: false
    });

    console.log(result);
    expect(result.verified).toBeFalsy();
  });
});
