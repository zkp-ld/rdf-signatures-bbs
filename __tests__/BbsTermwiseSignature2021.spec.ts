import jsigs from "jsonld-signatures";

import {
  exampleBls12381KeyPair,
  testDocument,
  testSignedDocument,
  testBadSignedDocument,
  testBadSignedDocumentWithIncompatibleSuite,
  customLoader,
  testVcDocument,
  testSignedVcDocument,
  testSignedVcDocumentJwk,
  testSignedDocumentMultiProofs,
  testSignedDocumentMultiBadProofs
} from "./__fixtures__";
import { Bls12381G2KeyPair, BbsTermwiseSignature2021 } from "../src/index";

const key = new Bls12381G2KeyPair(exampleBls12381KeyPair);

describe("BbsTermwiseSignature2021", () => {
  it("should sign with jsigs", async () => {
    const signed = await jsigs.sign(testDocument, {
      suite: new BbsTermwiseSignature2021({ key }),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader
    });
    expect(signed).toBeDefined();
  });

  it("should verify with jsigs", async () => {
    const verificationResult = await jsigs.verify(testSignedDocument, {
      suite: new BbsTermwiseSignature2021(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader
    });

    expect(verificationResult).toBeDefined();
    expect(verificationResult.verified).toBeTruthy();
  });

  it("should not verify bad sig with jsigs", async () => {
    const verificationResult = await jsigs.verify(testBadSignedDocument, {
      suite: new BbsTermwiseSignature2021(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader
    });
    expect(verificationResult).toBeDefined();
    expect(verificationResult.verified).toBeFalsy();
  });

  it("should not verify bad sig with imcompatible suite with jsigs", async () => {
    const verificationResult = await jsigs.verify(
      testBadSignedDocumentWithIncompatibleSuite,
      {
        suite: new BbsTermwiseSignature2021(),
        purpose: new jsigs.purposes.AssertionProofPurpose(),
        documentLoader: customLoader
      }
    );
    expect(verificationResult).toBeDefined();
    expect(verificationResult.verified).toBeFalsy();
  });

  it("should not verify with additional unsigned information with jsigs", async () => {
    const modfiedDocument = {
      ...testSignedDocument,
      unsignedClaim: "oops"
    };

    const verificationResult = await jsigs.verify(modfiedDocument, {
      suite: new BbsTermwiseSignature2021(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader
    });
    expect(verificationResult).toBeDefined();
    expect(verificationResult.verified).toBeFalsy();
  });

  it("should not verify with modified statement", async () => {
    const modfiedDocument = {
      ...testSignedDocument,
      email: "someOtherEmail@example.com"
    };

    const verificationResult = await jsigs.verify(modfiedDocument, {
      suite: new BbsTermwiseSignature2021(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader
    });
    expect(verificationResult).toBeDefined();
    expect(verificationResult.verified).toBeFalsy();
  });

  it("should sign verifiable credential with jsigs", async () => {
    const signed = await jsigs.sign(testVcDocument, {
      suite: new BbsTermwiseSignature2021({ key }),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader
    });
    expect(signed).toBeDefined();
  });

  it("should verify verifiable credential with jsigs", async () => {
    const verificationResult = await jsigs.verify(testSignedVcDocument, {
      suite: new BbsTermwiseSignature2021(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader
    });
    expect(verificationResult).toBeDefined();
    expect(verificationResult.verified).toBeTruthy();
  });

  it("should verify verifiable credential with JWK and jsigs", async () => {
    const verificationResult = await jsigs.verify(testSignedVcDocumentJwk, {
      suite: new BbsTermwiseSignature2021(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader
    });
    expect(verificationResult).toBeDefined();
    expect(verificationResult.verified).toBeTruthy();
  });

  it("should verify document with multiple proofs", async () => {
    const verificationResult = await jsigs.verify(
      testSignedDocumentMultiProofs,
      {
        suite: new BbsTermwiseSignature2021(),
        purpose: new jsigs.purposes.AssertionProofPurpose(),
        documentLoader: customLoader
      }
    );
    expect(verificationResult).toBeDefined();
    expect(verificationResult.verified).toBeTruthy();
  });

  it.skip("should not verify document with multiple proofs one of which is modified", async () => {
    // Skipped:  this looks like an unexpected behaviour for me, it turns out expected result,
    // according to the `jsonld-signatures` description.
    // See https://github.com/yamdan/jsonld-signatures-bbs/issues/2
    const verificationResult = await jsigs.verify(
      testSignedDocumentMultiBadProofs,
      {
        suite: new BbsTermwiseSignature2021(),
        purpose: new jsigs.purposes.AssertionProofPurpose(),
        documentLoader: customLoader
      }
    );
    expect(verificationResult).toBeDefined();
    expect(verificationResult.verified).toBeFalsy();
  });
});
