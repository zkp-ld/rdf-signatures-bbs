import jsigs from "jsonld-signatures";

import {
  exampleBls12381KeyPair,
  testRevealDocument,
  testSignedDocument,
  testProofDocument,
  customLoader,
  testPartialProofDocument,
  testBadPartialProofDocument,
  testSignedVcDocument,
  testRevealVcDocument,
  testPartialVcProof,
  testRevealAllDocument,
  testProofNestedVcDocument,
  testPartialProofNestedVcDocument,
  testBadPartialProofDocumentWithIncompatibleSuite
} from "./__fixtures__";
import {
  Bls12381G2KeyPair,
  BbsTermwiseSignatureProof2021,
  BbsTermwiseSignature2021
} from "../src/index";
import { getProofs } from "../src/utilities";

const key = new Bls12381G2KeyPair(exampleBls12381KeyPair);

describe("BbsTermwiseSignatureProof2021", () => {
  it("should derive proof", async () => {
    const suite = new BbsTermwiseSignatureProof2021({
      useNativeCanonize: false,
      key
    });

    const { proofs, document } = await getProofs({
      document: testSignedDocument,
      proofType: BbsTermwiseSignatureProof2021.supportedDerivedProofType,
      documentLoader: customLoader
    });

    let result: any = await suite.deriveProof({
      document,
      proof: proofs,
      revealDocument: testRevealDocument,
      documentLoader: customLoader
    });
    expect(result).toBeDefined();
  });

  it("should not verify derived document without proof", async () => {
    const suite = new BbsTermwiseSignatureProof2021({
      useNativeCanonize: false,
      key
    });

    const { proofs, document } = await getProofs({
      document: testSignedDocument,
      proofType: BbsTermwiseSignatureProof2021.supportedDerivedProofType,
      documentLoader: customLoader
    });

    let derivedProof: any = await suite.deriveProof({
      document,
      proof: proofs,
      revealDocument: testRevealDocument,
      documentLoader: customLoader
    });

    const result = await suite.verifyProof({
      document: derivedProof.document,
      proof: [], // remove proof
      documentLoader: customLoader,
      purpose: new jsigs.purposes.AssertionProofPurpose()
    });
    expect(result.verified).toBeFalsy();
  });

  it("should not verify partial derived proof with bad proof", async () => {
    const suite = new BbsTermwiseSignatureProof2021();

    const { proofs, document } = await getProofs({
      document: testBadPartialProofDocument,
      proofType: BbsTermwiseSignatureProof2021.proofType,
      documentLoader: customLoader
    });

    const result = await suite.verifyProof({
      document,
      proof: proofs,
      documentLoader: customLoader,
      purpose: new jsigs.purposes.AssertionProofPurpose()
    });
    expect(result.verified).toBeFalsy();
  });

  it("should not verify partial derived proof with incompatible suite", async () => {
    const suite = new BbsTermwiseSignatureProof2021();

    const { proofs, document } = await getProofs({
      document: testBadPartialProofDocumentWithIncompatibleSuite,
      proofType: BbsTermwiseSignatureProof2021.proofType,
      documentLoader: customLoader
    });

    const result = await suite.verifyProof({
      document,
      proof: proofs,
      documentLoader: customLoader,
      purpose: new jsigs.purposes.AssertionProofPurpose()
    });
    expect(result.verified).toBeFalsy();
  });

  it("should not derive proof with document featuring unsigned info", async () => {
    const suite = new BbsTermwiseSignatureProof2021();

    const input = {
      ...testSignedDocument,
      unsignedClaim: true
    };

    const { proofs, document } = await getProofs({
      document: input,
      proofType: BbsTermwiseSignature2021.proofType,
      documentLoader: customLoader
    });

    await expect(
      suite.deriveProof({
        document,
        proof: proofs,
        revealDocument: testRevealAllDocument,
        documentLoader: customLoader
      })
    ).rejects.toThrowError("Failed to create proof");
  });

  it("should not derived proof with document featuring modified info", async () => {
    const suite = new BbsTermwiseSignatureProof2021();

    const input = {
      ...testSignedDocument,
      email: "bad@example.com"
    };

    const { proofs, document } = await getProofs({
      document: input,
      proofType: BbsTermwiseSignature2021.proofType,
      documentLoader: customLoader
    });

    await expect(
      suite.deriveProof({
        document,
        proof: proofs,
        revealDocument: testRevealAllDocument,
        documentLoader: customLoader
      })
    ).rejects.toThrowError("Failed to create proof");
  });

  it("should not derived proof with document featuring missing info", async () => {
    const suite = new BbsTermwiseSignatureProof2021();

    type TestSignedDocumentType = {
      "@context": string[];
      "@type": string;
      firstName: string;
      lastName: string;
      jobTitle: string;
      telephone: string;
      email?: string;
      proof: {
        type: string;
        created: string;
        proofPurpose: string;
        proofValue: string;
        verificationMethod: string;
      };
    };

    const input: TestSignedDocumentType = {
      ...testSignedDocument
    };

    delete input.email;

    const { proofs, document } = await getProofs({
      document: input,
      proofType: BbsTermwiseSignature2021.proofType,
      documentLoader: customLoader
    });

    await expect(
      suite.deriveProof({
        document,
        proof: proofs,
        revealDocument: testRevealAllDocument,
        documentLoader: customLoader
      })
    ).rejects.toThrowError("Failed to create proof");
  });

  it("should derive proof revealing all statements", async () => {
    const suite = new BbsTermwiseSignatureProof2021({
      useNativeCanonize: false,
      key
    });

    const { proofs, document } = await getProofs({
      document: testSignedDocument,
      proofType: BbsTermwiseSignatureProof2021.supportedDerivedProofType,
      documentLoader: customLoader
    });

    const result = await suite.deriveProof({
      document,
      proof: proofs,
      revealDocument: testRevealAllDocument,
      documentLoader: customLoader
    });
    expect(result).toBeDefined();
  });

  it("should derive proof from vc", async () => {
    const suite = new BbsTermwiseSignatureProof2021({
      useNativeCanonize: false,
      key
    });

    const { proofs, document } = await getProofs({
      document: testSignedVcDocument,
      proofType: BbsTermwiseSignatureProof2021.supportedDerivedProofType,
      documentLoader: customLoader
    });

    const result = await suite.deriveProof({
      document,
      proof: proofs,
      revealDocument: testRevealVcDocument,
      documentLoader: customLoader
    });
    expect(result).toBeDefined();
  });

  it("should verify derived proof", async () => {
    const suite = new BbsTermwiseSignatureProof2021();

    const { proofs, document } = await getProofs({
      document: testProofDocument,
      proofType: BbsTermwiseSignatureProof2021.proofType,
      documentLoader: customLoader
    });

    const result = await suite.verifyProof({
      document,
      proof: proofs,
      documentLoader: customLoader,
      purpose: new jsigs.purposes.AssertionProofPurpose()
    });
    expect(result.verified).toBeTruthy();
  });

  it("should verify partial derived proof", async () => {
    const suite = new BbsTermwiseSignatureProof2021();

    const { proofs, document } = await getProofs({
      document: testPartialProofDocument,
      proofType: BbsTermwiseSignatureProof2021.proofType,
      documentLoader: customLoader
    });

    const result = await suite.verifyProof({
      document,
      proof: proofs,
      documentLoader: customLoader,
      purpose: new jsigs.purposes.AssertionProofPurpose()
    });
    expect(result.verified).toBeTruthy();
  });

  it("should verify a fully revealed derived proof that uses nesting from a vc", async () => {
    const suite = new BbsTermwiseSignatureProof2021();

    const { proofs, document } = await getProofs({
      document: testProofNestedVcDocument,
      proofType: BbsTermwiseSignatureProof2021.proofType,
      documentLoader: customLoader
    });

    const result = await suite.verifyProof({
      document,
      proof: proofs,
      documentLoader: customLoader,
      purpose: new jsigs.purposes.AssertionProofPurpose()
    });
    expect(result.verified).toBeTruthy();
  });

  it("should verify a partially revealed derived proof that uses nesting from a vc", async () => {
    const suite = new BbsTermwiseSignatureProof2021();

    const { proofs, document } = await getProofs({
      document: testPartialProofNestedVcDocument,
      proofType: BbsTermwiseSignatureProof2021.proofType,
      documentLoader: customLoader
    });

    const result = await suite.verifyProof({
      document,
      proof: proofs,
      documentLoader: customLoader,
      purpose: new jsigs.purposes.AssertionProofPurpose()
    });
    expect(result.verified).toBeTruthy();
  });

  it("should verify partial derived proof from vc", async () => {
    const suite = new BbsTermwiseSignatureProof2021();

    const { proofs, document } = await getProofs({
      document: testPartialVcProof,
      proofType: BbsTermwiseSignatureProof2021.proofType,
      documentLoader: customLoader
    });

    const result = await suite.verifyProof({
      document,
      proof: proofs,
      documentLoader: customLoader,
      purpose: new jsigs.purposes.AssertionProofPurpose()
    });
    expect(result.verified).toBeTruthy();
  });
});
