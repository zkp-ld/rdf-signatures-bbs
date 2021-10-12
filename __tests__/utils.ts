import jsigs from "jsonld-signatures";
import { deriveProofMulti, verifyProofMulti } from "../src/index";
import { getProofs } from "../src/utilities";

export const signDeriveVerifyMulti = async (
  vcRevealKeys: any[],
  hiddenUris: string[],
  customLoader: any,
  signSuite: any,
  proofSuite: any
) => {
  // Issuers issue VCs
  for (const vcRevealKey of vcRevealKeys) {
    const { vc, key } = vcRevealKey;

    const signedVc = await jsigs.sign(vc, {
      suite: new signSuite({ key }),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader,
      expansionMap: false
    });
    expect(signedVc).toBeDefined();

    vcRevealKey["signedVc"] = signedVc;
  }

  // Holder verifies VCs
  for (const { signedVc } of vcRevealKeys) {
    const verifiedVc = await jsigs.verify(signedVc, {
      suite: new signSuite(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader,
      expansionMap: false
    });
    expect(verifiedVc.verified).toBeTruthy();
  }

  // Holder gets proofs
  const suite = new proofSuite();
  for (const vcRevealKey of vcRevealKeys) {
    const { proofs, document } = await getProofs({
      document: vcRevealKey.signedVc,
      proofType: suite.supportedDeriveProofType,
      documentLoader: customLoader
    });

    if (proofs.length === 0) {
      throw new Error(
        `There were not any proofs provided that can be used to derive a proof with this suite.`
      );
    }

    vcRevealKey["proof"] = proofs[0];
    vcRevealKey["document"] = document;
  }

  // Holder derives proof
  const derivedProofs = await suite.deriveProofMulti({
    inputDocuments: vcRevealKeys,
    documentLoader: customLoader,
    hiddenUris
  });
  expect(derivedProofs.length).toEqual(vcRevealKeys.length);

  console.log(`
# URIs to be hidden:
${JSON.stringify(hiddenUris, null, 2)}`);
  for (let i = 0; i < vcRevealKeys.length; i++) {
    console.log(`
# issued VCs (${i}):
${JSON.stringify(vcRevealKeys[i].signedVc, null, 2)}`);
    console.log(`
# reveal documents (${i}):
${JSON.stringify(vcRevealKeys[i].revealDocument, null, 2)}`);
    console.log(`
# derived proofs (${i}):
${JSON.stringify(derivedProofs[i], null, 2)}`);
  }

  // Verifier verifies proof
  const result = await suite.verifyProofMulti({
    inputDocuments: derivedProofs,
    documentLoader: customLoader,
    purpose: new jsigs.purposes.AssertionProofPurpose()
  });
  console.log(`
# Verifier verifies Proof:
${JSON.stringify(result, null, 2)}`);

  expect(result.verified).toBeTruthy();
};

export const signDeriveVerifyMultiJSigLike = async (
  vcRevealKeys: any[],
  hiddenUris: string[],
  customLoader: any,
  signSuite: any,
  proofSuite: any
) => {
  const derivedProofs = await signDeriveMultiJSigLike(
    vcRevealKeys,
    hiddenUris,
    customLoader,
    signSuite,
    proofSuite
  );

  // Verifier verifies proof
  const result = await verifyProofMulti(derivedProofs, {
    suite: new proofSuite(),
    purpose: new jsigs.purposes.AssertionProofPurpose(),
    documentLoader: customLoader,
    expansionMap: false
  });

  console.log(`
# Verifier verifies Proof:
${JSON.stringify(result, null, 2)}`);

  expect(result.verified).toBeTruthy();
};

export const signDeriveMultiJSigLike = async (
  vcRevealKeys: any[],
  hiddenUris: string[],
  customLoader: any,
  signSuite: any,
  proofSuite: any
): Promise<any[]> => {
  // Issuers issues VCs
  const documents: [any, any][] = await Promise.all(
    vcRevealKeys.map(
      async ({ vc, revealDocument, key }): Promise<[any, any]> => {
        const signedVc = await jsigs.sign(vc, {
          suite: new signSuite({ key }),
          purpose: new jsigs.purposes.AssertionProofPurpose(),
          documentLoader: customLoader,
          expansionMap: false
        });
        expect(signedVc).toBeDefined();
        return [signedVc, revealDocument];
      }
    )
  );

  // Holder verifies VCs
  for (const [signedVc, _] of documents) {
    const verifiedVc = await jsigs.verify(signedVc, {
      suite: new signSuite(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader,
      expansionMap: false
    });
    expect(verifiedVc.verified).toBeTruthy();
  }

  // Holder derives proof
  const derivedProofs = await deriveProofMulti(documents, {
    hiddenUris,
    suite: new proofSuite(),
    documentLoader: customLoader
  });

  expect(derivedProofs.length).toEqual(vcRevealKeys.length);

  console.log(`
# URIs to be hidden:
${JSON.stringify(hiddenUris, null, 2)}`);
  for (let i = 0; i < documents.length; i++) {
    console.log(`
# issued VCs (${i}):
${JSON.stringify(documents[i][0], null, 2)}`);
    console.log(`
# reveal documents (${i}):
${JSON.stringify(documents[i][1], null, 2)}`);
    console.log(`
# derived proofs (${i}):
${JSON.stringify(derivedProofs[i], null, 2)}`);
  }

  return derivedProofs;
};
