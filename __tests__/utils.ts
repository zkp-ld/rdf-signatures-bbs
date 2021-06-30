import jsigs from "jsonld-signatures";
import {
  BbsBlsSignature2020,
  BbsBlsSignatureProof2020,
  deriveProof
} from "../src/index";
import { getProofs } from "../src/utilities";

export const signDeriveVerify = async (
  vc: any,
  reveal: any,
  subject: any,
  key: any,
  customLoader: any
) => {
  console.log(`
# Issuer: prepare Credential to be signed:
${JSON.stringify(vc, null, 2)}`);

  // Issuer issues VC
  const signedVc = await jsigs.sign(vc, {
    suite: new BbsBlsSignature2020({ key }),
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
    suite: new BbsBlsSignature2020(),
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
    suite: new BbsBlsSignatureProof2020(),
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
    proofType: BbsBlsSignatureProof2020.proofType,
    documentLoader: customLoader
  });
  const suite = new BbsBlsSignatureProof2020();
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
