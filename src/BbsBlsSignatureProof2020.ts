/*
 * Copyright 2020 - MATTR Limited
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* eslint-disable @typescript-eslint/no-explicit-any */
import jsonld from "jsonld";
import { suites, SECURITY_CONTEXT_URL } from "jsonld-signatures";
import { blsCreateProof, blsVerifyProof } from "@mattrglobal/bbs-signatures";
import {
  DeriveProofOptions,
  VerifyProofOptions,
  CreateVerifyDataOptions,
  CanonizeOptions,
  CanonicalizeOptions,
  CanonicalizeResult,
  SkolemizeResult,
  RevealOptions,
  RevealResult,
  Statement
} from "./types";
import { BbsBlsSignature2020 } from "./BbsBlsSignature2020";
import { randomBytes } from "@stablelib/random";
import { VerifyProofResult } from "./types/VerifyProofResult";
import { Bls12381G2KeyPair } from "@mattrglobal/bls12381-key-pair";
import { StringStatement } from "./StringStatement";

export class BbsBlsSignatureProof2020 extends suites.LinkedDataProof {
  constructor({ useNativeCanonize, key, LDKeyClass }: any = {}) {
    super({
      type: "sec:BbsBlsSignatureProof2020"
    });

    this.proof = {
      "@context": [
        {
          sec: "https://w3id.org/security#",
          proof: {
            "@id": "sec:proof",
            "@type": "@id",
            "@container": "@graph"
          }
        },
        "https://w3id.org/security/bbs/v1"
      ],
      type: "BbsBlsSignatureProof2020"
    };
    this.mappedDerivedProofType =
      "https://w3id.org/security#BbsBlsSignature2020";
    this.supportedDeriveProofType =
      BbsBlsSignatureProof2020.supportedDerivedProofType;

    this.LDKeyClass = LDKeyClass ?? Bls12381G2KeyPair;
    this.proofSignatureKey = "proofValue";
    this.key = key;
    this.useNativeCanonize = useNativeCanonize;
    this.Suite = BbsBlsSignature2020;
    this.Statement = StringStatement;
  }

  /**
   * Derive a proof from a proof and reveal document
   *
   * @param options {object} options for deriving a proof.
   *
   * @returns {Promise<object>} Resolves with the derived proof object.
   */
  async deriveProof(options: DeriveProofOptions): Promise<object> {
    const {
      document,
      proof,
      revealDocument,
      documentLoader,
      expansionMap,
      skipProofCompaction
    } = options;
    let { nonce } = options;

    // Validate that the input proof document has a proof compatible with this suite
    if (
      !BbsBlsSignatureProof2020.supportedDerivedProofType.includes(proof.type)
    ) {
      throw new TypeError(
        `proof document proof incompatible, expected proof types of ${JSON.stringify(
          BbsBlsSignatureProof2020.supportedDerivedProofType
        )} received ${proof.type}`
      );
    }

    //Extract the BBS signature from the input proof
    const signature = Buffer.from(proof[this.proofSignatureKey], "base64");

    // Initialize the signature suite
    const suite = new this.Suite();

    // Initialize the derived proof
    let derivedProof;
    if (this.proof) {
      // use proof JSON-LD document passed to API
      derivedProof = await jsonld.compact(this.proof, SECURITY_CONTEXT_URL, {
        documentLoader,
        expansionMap,
        compactToRelative: false
      });
    } else {
      // create proof JSON-LD document
      derivedProof = { "@context": SECURITY_CONTEXT_URL };
    }

    // ensure proof type is set
    derivedProof.type = this.type;

    // canonicalize: get N-Quads from JSON-LD
    const { documentStatements, proofStatements } = await this.canonicalize(
      document,
      proof,
      {
        suite,
        documentLoader,
        expansionMap,
        skipProofCompaction
      }
    );

    // skolemize: name all the blank nodes
    const {
      skolemizedDocument,
      skolemizedDocumentStatements
    } = await this.skolemize(documentStatements);

    // reveal: extract revealed parts using JSON-LD Framing
    const { revealedDocument, revealedDocumentStatements } = await this.reveal(
      skolemizedDocument,
      revealDocument,
      {
        suite,
        documentLoader,
        expansionMap
      }
    );

    // getIndicies: calculate reveal indicies
    const revealIndicies = this.getIndicies(
      skolemizedDocumentStatements,
      revealedDocumentStatements,
      proofStatements
    );

    // Create a nonce if one is not supplied
    if (!nonce) {
      nonce = await randomBytes(50);
    }

    // Set the nonce on the derived proof
    derivedProof.nonce = Buffer.from(nonce).toString("base64");

    // FOR DEBUG: output console.log
    this.logRevealedStatements(
      skolemizedDocumentStatements,
      proofStatements,
      revealedDocumentStatements
    );

    // Fetch the verification method
    const verificationMethod = await this.getVerificationMethod({
      proof,
      document,
      documentLoader,
      expansionMap
    });

    // Construct a key pair class from the returned verification method
    const key = await this.LDKeyClass.from(verificationMethod);

    // createProof: create BBS+ proof
    const outputProof = await this.createProof(
      documentStatements,
      proofStatements,
      nonce,
      revealIndicies,
      signature,
      key.publicKeyBuffer
    );

    // Set the proof value on the derived proof
    derivedProof.proofValue = Buffer.from(outputProof).toString("base64");

    // Set the relevant proof elements on the derived proof from the input proof
    derivedProof.verificationMethod = proof.verificationMethod;
    derivedProof.proofPurpose = proof.proofPurpose;
    derivedProof.created = proof.created;

    return {
      document: { ...revealedDocument },
      proof: derivedProof
    };
  }

  /**
   * @param options {object} options for verifying the proof.
   *
   * @returns {Promise<{object}>} Resolves with the verification result.
   */
  async verifyProof(options: VerifyProofOptions): Promise<VerifyProofResult> {
    const { document, documentLoader, expansionMap, purpose } = options;
    const { proof } = options;

    try {
      proof.type = this.mappedDerivedProofType;

      // canonicalize: get N-Quads from JSON-LD
      const {
        documentStatements: skolemizedDocumentStatements,
        proofStatements
      } = await this.canonicalize(document, proof, {
        suite: this,
        documentLoader,
        expansionMap
      });

      // deskolemize: unname all the blank nodes
      const documentStatements = await this.deskolemize(
        skolemizedDocumentStatements
      );

      // FOR DEBUG: output console.log
      this.logVerifiedStatements(
        proof.proofValue,
        documentStatements,
        proofStatements
      );

      // Combine all the statements to be verified
      const statementsToVerify: Uint8Array[] = proofStatements
        .concat(documentStatements)
        .flatMap((item: Statement) => item.serialize());

      // Fetch the verification method
      const verificationMethod = await this.getVerificationMethod({
        proof,
        document,
        documentLoader,
        expansionMap
      });

      const key = await this.LDKeyClass.from(verificationMethod);

      // Verify the proof
      const verified = await blsVerifyProof({
        proof: new Uint8Array(Buffer.from(proof.proofValue, "base64")),
        publicKey: new Uint8Array(key.publicKeyBuffer),
        messages: statementsToVerify,
        nonce: new Uint8Array(Buffer.from(proof.nonce as string, "base64"))
      });

      // Ensure proof was performed for a valid purpose
      const { valid, error } = await purpose.validate(proof, {
        document,
        suite: this,
        verificationMethod,
        documentLoader,
        expansionMap
      });
      if (!valid) {
        throw error;
      }

      return verified;
    } catch (error) {
      return { verified: false, error };
    }
  }

  async canonize(input: any, options: CanonizeOptions): Promise<string> {
    const { documentLoader, expansionMap, skipExpansion } = options;
    return jsonld.canonize(input, {
      algorithm: "URDNA2015",
      format: "application/n-quads",
      documentLoader,
      expansionMap,
      skipExpansion,
      useNative: this.useNativeCanonize
    });
  }

  async canonizeProof(proof: any, options: CanonizeOptions): Promise<string> {
    const { documentLoader, expansionMap } = options;
    proof = { ...proof };

    delete proof.nonce;
    delete proof.proofValue;

    return this.canonize(proof, {
      documentLoader,
      expansionMap,
      skipExpansion: false
    });
  }

  /**
   * @param document {CreateVerifyDataOptions} options to create verify data
   *
   * @returns {Promise<Statement[]>}.
   */
  async createVerifyData(
    options: CreateVerifyDataOptions
  ): Promise<Statement[]> {
    const { proof, document, documentLoader, expansionMap } = options;

    const proofStatements = await this.createVerifyProofData(proof, {
      documentLoader,
      expansionMap
    });
    const documentStatements = await this.createVerifyDocumentData(document, {
      documentLoader,
      expansionMap
    });

    // concatenate c14n proof options and c14n document
    return proofStatements.concat(documentStatements);
  }

  /**
   * @param nQuads {string} canonized RDF N-Quads as a string
   *
   * @returns {Statement[]} an array of statements
   */
  getStatements(nQuads: string): Statement[] {
    return nQuads
      .split("\n")
      .filter(_ => _.length > 0)
      .map((s: string) => new this.Statement(s));
  }

  /**
   * @param proof to canonicalize
   * @param options to create verify data
   *
   * @returns {Promise<Statement[]>}.
   */
  async createVerifyProofData(
    proof: any,
    { documentLoader, expansionMap }: any
  ): Promise<Statement[]> {
    const c14nProofOptions = await this.canonizeProof(proof, {
      documentLoader,
      expansionMap
    });

    return this.getStatements(c14nProofOptions);
  }

  /**
   * @param document to canonicalize
   * @param options to create verify data
   *
   * @returns {Promise<Statement[]>}.
   */
  async createVerifyDocumentData(
    document: any,
    { documentLoader, expansionMap }: any
  ): Promise<Statement[]> {
    const c14nDocument = await this.canonize(document, {
      documentLoader,
      expansionMap
    });

    return this.getStatements(c14nDocument);
  }

  /**
   * @param document {object} to be signed.
   * @param proof {object}
   * @param documentLoader {function}
   * @param expansionMap {function}
   */
  async getVerificationMethod({ proof, documentLoader }: any): Promise<object> {
    let { verificationMethod } = proof;

    if (typeof verificationMethod === "object") {
      verificationMethod = verificationMethod.id;
    }
    if (!verificationMethod) {
      throw new Error('No "verificationMethod" found in proof.');
    }

    // Note: `expansionMap` is intentionally not passed; we can safely drop
    // properties here and must allow for it
    const result = await jsonld.frame(
      verificationMethod,
      {
        "@context": SECURITY_CONTEXT_URL,
        "@embed": "@always",
        id: verificationMethod
      },
      {
        documentLoader,
        compactToRelative: false,
        expandContext: SECURITY_CONTEXT_URL
      }
    );
    if (!result) {
      throw new Error(`Verification method ${verificationMethod} not found.`);
    }

    // ensure verification method has not been revoked
    if (result.revoked !== undefined) {
      throw new Error("The verification method has been revoked.");
    }

    return result;
  }

  static proofType = [
    "BbsBlsSignatureProof2020",
    "sec:BbsBlsSignatureProof2020",
    "https://w3id.org/security#BbsBlsSignatureProof2020"
  ];

  static supportedDerivedProofType = [
    "BbsBlsSignature2020",
    "sec:BbsBlsSignature2020",
    "https://w3id.org/security#BbsBlsSignature2020"
  ];

  /**
   * @param documentStatements {string[]} all the document statements (N-Quads)
   * @param proofStatements {string[]} proof statements (N-Quads)
   * @param revealedDocumentStatements {string[]} only revealed document statements (N-Quads)
   *
   * @returns {void} output revealed statements to console log
   */
  logRevealedStatements(
    skolemizedDocumentStatements: Statement[],
    proofStatements: Statement[],
    revealedDocumentStatements: Statement[]
  ): void {
    const numberOfProofStatements = proofStatements.length;
    const numberedRevealedDocumentStatements = revealedDocumentStatements.map(
      statement =>
        `# ${skolemizedDocumentStatements.findIndex(
          e => e.toString() === statement.toString()
        ) + numberOfProofStatements}\n${statement}`
    );

    const numberedProofStatements = proofStatements.map(
      (statement, i) => `# ${i}\n${statement}`
    );

    const allStatements: string[] = numberedProofStatements.concat(
      numberedRevealedDocumentStatements
    );

    console.log(`
# statements to be revealed
${allStatements.join("\n")}`);
  }

  /**
   * @param documentStatements {string[]} all the document statements (N-Quads)
   * @param proofStatements {string[]} proof statements (N-Quads)
   *
   * @returns {void} output revealed statements to console log
   */
  logVerifiedStatements(
    proofValue: string,
    documentStatements: Statement[],
    proofStatements: Statement[]
  ): void {
    const verifiedStatements = proofStatements.concat(documentStatements);

    console.log(`
# proofValue (base64-decoded)
${Buffer.from(proofValue, "base64").toString("hex")}

# statements to be verified
${verifiedStatements.join("\n")}`);
  }

  /**
   * Get canonical N-Quads from JSON-LD
   *
   * @param document to canonicalize
   * @param proof to canonicalize
   * @param options to create verify data
   *
   * @returns {Promise<CanonicalizeResult>} canonicalized statements
   */
  async canonicalize(
    document: string,
    proof: string,
    options: CanonicalizeOptions
  ): Promise<CanonicalizeResult> {
    const {
      suite,
      documentLoader,
      expansionMap,
      skipProofCompaction
    } = options;

    // Get the input document statements
    const documentStatements: Statement[] = await suite.createVerifyDocumentData(
      document,
      {
        documentLoader,
        expansionMap,
        compactProof: !skipProofCompaction
      }
    );

    // Get the proof statements
    const proofStatements: Statement[] = await suite.createVerifyProofData(
      proof,
      {
        documentLoader,
        expansionMap,
        compactProof: !skipProofCompaction
      }
    );

    return { documentStatements, proofStatements };
  }

  /**
   * Name all the blank nodes
   *
   * @param documentStatements to skolemize
   *
   * @returns {Promise<SkolemizeResult>} skolemized JSON-LD document and statements
   */
  async skolemize(documentStatements: Statement[]): Promise<SkolemizeResult> {
    // Transform any blank node identifiers for the input
    // document statements into actual node identifiers
    // e.g., _:c14n0 => <urn:bnid:_:c14n0>
    const skolemizedDocumentStatements = documentStatements.map(element =>
      element.skolemize()
    );

    // Transform the resulting RDF statements back into JSON-LD
    const skolemizedDocument: string = await jsonld.fromRDF(
      skolemizedDocumentStatements.join("\n")
    );

    return { skolemizedDocument, skolemizedDocumentStatements };
  }

  /**
   * Unname all the blank nodes
   *
   * @param documentStatements to deskolemize
   *
   * @returns {Promise<DeskolemizeResult>} deskolemized JSON-LD document and statements
   */
  async deskolemize(
    skolemizedDocumentStatements: Statement[]
  ): Promise<Statement[]> {
    // Transform the blank node identifier placeholders for the document statements
    // back into actual blank node identifiers
    // e.g., <urn:bnid:_:c14n0> => _:c14n0
    const documentStatements = skolemizedDocumentStatements.map(element =>
      element.deskolemize()
    );
    return documentStatements;
  }

  /**
   * Extract revealed parts using JSON-LD Framing
   *
   * @param skolemizedDocument JSON-LD document
   * @param revealDocument JSON-LD frame
   * @param options for framing and createVerifyData
   *
   * @returns {Promise<RevealResult>} revealed JSON-LD document and statements
   */
  async reveal(
    skolemizedDocument: string,
    revealDocument: string,
    options: RevealOptions
  ): Promise<RevealResult> {
    const { suite, documentLoader, expansionMap } = options;

    // Frame the result to create the reveal document result
    const revealedDocument = await jsonld.frame(
      skolemizedDocument,
      revealDocument,
      { documentLoader }
    );

    // Canonicalize the resulting reveal document
    const revealedDocumentStatements = await suite.createVerifyDocumentData(
      revealedDocument,
      {
        documentLoader,
        expansionMap
      }
    );

    return { revealedDocument, revealedDocumentStatements };
  }

  /**
   * Calculate reveal indicies
   *
   * @param skolemizedDocumentStatements full document statements
   * @param revealedDocumentStatements revealed document statements
   * @param proofStatements proof statements
   *
   * @returns {Promise<RevealResult>} revealed JSON-LD document and statements
   */
  getIndicies(
    skolemizedDocumentStatements: Statement[],
    revealedDocumentStatements: Statement[],
    proofStatements: Statement[]
  ): number[] {
    //Get the indicies of the revealed statements from the transformed input document offset
    //by the number of proof statements
    const numberOfProofStatements = proofStatements.length;

    //Always reveal all the statements associated to the original proof
    //these are always the first statements in the normalized form
    const proofRevealIndicies = Array.from(
      Array(numberOfProofStatements).keys()
    );

    //Reveal the statements indicated from the reveal document
    const documentRevealIndicies = revealedDocumentStatements.map(
      key =>
        skolemizedDocumentStatements.findIndex(
          e => e.toString() === key.toString()
        ) + numberOfProofStatements
    );

    // Check there is not a mismatch
    if (documentRevealIndicies.length !== revealedDocumentStatements.length) {
      throw new Error(
        "Some statements in the reveal document not found in original proof"
      );
    }

    // Combine all indicies to get the resulting list of revealed indicies
    return proofRevealIndicies.concat(documentRevealIndicies);
  }

  /**
   * Create BBS+ proof
   *
   * @param documentStatements full document statements
   * @param proofStatements proof statements
   * @param nonce nonce to prevent replay attacks
   * @param revealIndicies indicies to indicate revealed statements
   * @param signature original BBS+ signature
   * @param issuerPublicKey issuer's public key
   *
   * @returns {Promise<Uint8Array>} derived proof value
   */
  async createProof(
    documentStatements: Statement[],
    proofStatements: Statement[],
    nonce: Uint8Array,
    revealIndicies: number[],
    signature: Buffer,
    issuerPublicKey: Buffer
  ): Promise<Uint8Array> {
    // Combine all the input statements that
    // were originally signed to generate the proof
    const allInputStatements: Uint8Array[] = proofStatements
      .concat(documentStatements)
      .flatMap((item: Statement) => item.serialize());

    // Compute the proof
    return await blsCreateProof({
      signature: new Uint8Array(signature),
      publicKey: new Uint8Array(issuerPublicKey),
      messages: allInputStatements,
      nonce: nonce,
      revealed: revealIndicies
    });
  }
}
