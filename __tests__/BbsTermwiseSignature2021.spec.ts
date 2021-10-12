import jsigs from "jsonld-signatures";

import {
  exampleBls12381KeyPair,
  testDocument,
  testSignedDocument,
  testBadSignedDocument,
  customLoader,
  testVcDocument,
  testSignedVcDocument
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
});
