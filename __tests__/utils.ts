import jsigs from "jsonld-signatures";
import { deriveProof } from "../src/index";
import { getProofs } from "../src/utilities";

export const signDeriveVerify = async (
  vc: any,
  reveal: any,
  subject: any,
  key: any,
  customLoader: any,
  signSuite: any,
  proofSuite: any
) => {
  console.log(`
# Issuer: prepare Credential to be signed:
${JSON.stringify(vc, null, 2)}`);

  // Issuer issues VC
  const signedVc = await jsigs.sign(vc, {
    suite: new signSuite({ key }),
    purpose: new jsigs.purposes.AssertionProofPurpose(),
    documentLoader: customLoader,
    expansionMap: false,
    compactProof: true
  });
  expect(signedVc).toBeDefined();

  console.log(`
# Issuer: issue VC:
${JSON.stringify(signedVc, null, 2)}`);

  // Holder verifies VC
  const verifiedVc = await jsigs.verify(signedVc, {
    suite: new signSuite(),
    purpose: new jsigs.purposes.AssertionProofPurpose(),
    documentLoader: customLoader,
    expansionMap: false,
    compactProof: true
  });
  expect(verifiedVc.verified).toBeTruthy();

  console.log(`
# Holder: verify VC:
${JSON.stringify(verifiedVc, null, 2)}`);

  console.log(`
# Holder: prepare Reveal Document as JSON-LD Frame:
${JSON.stringify(reveal, null, 2)}`);

  // Holder derives Proof
  const derivedProof = await deriveProof(signedVc, reveal, {
    suite: new proofSuite(),
    documentLoader: customLoader
  });
  //expect(derivedProof.credentialSubject).toEqual(subject);
  expect(derivedProof.credentialSubject).toBeDefined();

  console.log(`
# Holder: derive Proof:
${JSON.stringify(derivedProof, null, 2)}`);

  // Verifier verifies proof
  const { document, proofs } = await getProofs({
    document: derivedProof,
    proofType: proofSuite.proofType,
    documentLoader: customLoader
  });
  const suite = new proofSuite();
  const result = await suite.verifyProof({
    document,
    proof: proofs[0],
    documentLoader: customLoader,
    purpose: new jsigs.purposes.AssertionProofPurpose()
  });
  expect(result.verified).toBeTruthy();

  console.log(`
# Verifier: verify Proof:
${JSON.stringify(result, null, 2)}`);
};

export const signDeriveVerifyMulti = async (
  vcRevealKeys: any[],
  customLoader: any,
  signSuite: any,
  proofSuite: any
) => {
  for (const vcRevealKey of vcRevealKeys) {
    const [vc, reveal, key] = vcRevealKey;

    console.log(`
    # Issuer: prepare Credential to be signed:
    ${JSON.stringify(vc, null, 2)}`);

    // Issuer issues VC
    const signedVc = await jsigs.sign(vc, {
      suite: new signSuite({ key }),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader,
      expansionMap: false,
      compactProof: true
    });
    expect(signedVc).toBeDefined();

    console.log(`
    # Issuer: issue VC:
    ${JSON.stringify(signedVc, null, 2)}`);

    // Holder verifies VC
    const verifiedVc = await jsigs.verify(signedVc, {
      suite: new signSuite(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader: customLoader,
      expansionMap: false,
      compactProof: true
    });
    expect(verifiedVc.verified).toBeTruthy();

    console.log(`
    # Holder: verify VC:
    ${JSON.stringify(verifiedVc, null, 2)}`);

    console.log(`
    # Holder: prepare Reveal Document as JSON-LD Frame:
    ${JSON.stringify(reveal, null, 2)}`);
  }
};
