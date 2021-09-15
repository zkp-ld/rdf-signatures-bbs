/* eslint-disable @typescript-eslint/no-explicit-any */
import jsonld from "jsonld";
import { SECURITY_CONTEXT_URL } from "jsonld-signatures";
import { BbsBlsSignatureProof2020 } from "./BbsBlsSignatureProof2020";
import { BbsBlsSignatureTermwise2020 } from "./BbsBlsSignatureTermwise2020";
import {
  blsCreateProofMulti,
  blsVerifyProofMulti
} from "@yamdan/bbs-signatures";
import {
  Statement,
  CanonicalizeOptions,
  TermwiseCanonicalizeResult,
  DeriveProofMultiOptions,
  VerifyProofMultiOptions,
  VerifyProofResult,
  VerifyProofMultiResult
} from "./types";
import { TermwiseStatement } from "./TermwiseStatement";
import { randomBytes } from "@stablelib/random";

export class BbsBlsSignatureProofTermwise2020 extends BbsBlsSignatureProof2020 {
  constructor(options: any = {}) {
    super(options);
    this.Suite = BbsBlsSignatureTermwise2020;
    this.Statement = TermwiseStatement;
  }

  /**
   * Get canonical N-Quads from JSON-LD
   *
   * @param document to canonicalize
   * @param proof to canonicalize
   * @param options to create verify data
   *
   * @returns {Promise<TermwiseCanonicalizeResult>} canonicalized statements
   */
  async canonicalize(
    document: string,
    proof: string,
    options: CanonicalizeOptions
  ): Promise<TermwiseCanonicalizeResult> {
    const {
      suite,
      documentLoader,
      expansionMap,
      skipProofCompaction
    } = options;

    // Get the input document statements
    const documentStatements: TermwiseStatement[] = await suite.createVerifyDocumentData(
      document,
      {
        documentLoader,
        expansionMap,
        compactProof: !skipProofCompaction
      }
    );

    // Get the proof statements
    const proofStatements: TermwiseStatement[] = await suite.createVerifyProofData(
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
   * Unname all the blank nodes
   *
   * @param documentStatements to deskolemize
   *
   * @returns {Promise<DeskolemizeResult>} deskolemized JSON-LD document and statements
   */
  async deskolemize(
    skolemizedDocumentStatements: TermwiseStatement[]
  ): Promise<TermwiseStatement[]> {
    // Transform the blank node identifier placeholders for the document statements
    // back into actual blank node identifiers
    // e.g., <urn:bnid:_:c14n0> => _:c14n0
    const documentStatements = skolemizedDocumentStatements.map(element =>
      element.deskolemize()
    );
    return documentStatements;
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
    const NUM_OF_TERMS_IN_STATEMENT = 4;

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
    const BaseRevealIndicies = proofRevealIndicies.concat(
      documentRevealIndicies
    );

    // Expand indicies to fit termwise encoding
    // e.g., [0, 2, 5] -> [0,1,2,3, 8,9,10,11, 20,21,22,23]
    const revealIndicies = BaseRevealIndicies.flatMap(index =>
      [...Array(NUM_OF_TERMS_IN_STATEMENT).keys()].map(
        i => index * NUM_OF_TERMS_IN_STATEMENT + i
      )
    );
    return revealIndicies;
  }

  /**
   * Derive a proof from multiple proofs and reveal documents
   *
   * @param options {object} options for deriving a proof.
   *
   * @returns {Promise<object>} Resolves with the derived proof object.
   */
  async deriveProofMulti(options: DeriveProofMultiOptions): Promise<object> {
    const {
      inputDocuments,
      documentLoader,
      expansionMap,
      skipProofCompaction,
      hiddenUris
    } = options;
    let { nonce } = options;

    // Create a nonce if one is not supplied
    if (!nonce) {
      nonce = await randomBytes(50);
    }

    const termsArray: Uint8Array[][] = [];
    const revealIndiciesArray: number[][] = [];
    const issuerPublicKeyArray: Buffer[] = [];
    const signatureArray: Buffer[] = [];
    const revealedDocuments: any = [];
    const derivedProofs: any = [];

    const equivs: Map<string, [number, number][]> = new Map(
      hiddenUris.map(uri => [`<${uri}>`, []])
    );

    let index = 0;
    for (const { document, proof, revealDocument } of inputDocuments) {
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

      // Extract the BBS signature from the input proof
      const signature = Buffer.from(proof[this.proofSignatureKey], "base64");
      signatureArray.push(signature);

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

      // concat proof and document to generate
      const terms = proofStatements
        .concat(documentStatements)
        .flatMap((item: TermwiseStatement) => item.toTerms());

      termsArray.push(
        terms.map((term: string) => new Uint8Array(Buffer.from(term)))
      );

      // skolemize: name all the blank nodes
      // e.g., _:c14n0 -> urn:bnid:_:c14n0
      const {
        skolemizedDocument,
        skolemizedDocumentStatements
      } = await this.skolemize(documentStatements);

      // reveal: extract revealed parts using JSON-LD Framing
      const {
        revealedDocument,
        revealedDocumentStatements
      } = await this.reveal(skolemizedDocument, revealDocument, {
        suite,
        documentLoader,
        expansionMap
      });

      // prepare anonymized JSON-LD document to be revealed to verifier
      // by replacing hiddenURIs by anonymized IDs
      // (e.g., "did:anon:0", tentatively...)
      let anonymizedRevealedDocument = { ...revealedDocument };
      const anonymizeDocument = (doc: any) => {
        for (const [k, v] of Object.entries(doc)) {
          if (typeof v === "object") {
            anonymizeDocument(v);
          } else if (typeof v === "string") {
            const iid = hiddenUris.indexOf(v);
            if (iid != -1) {
              doc[k] = `did:anon:${iid}`;
            }
          }
        }
      };
      anonymizeDocument(anonymizedRevealedDocument);
      revealedDocuments.push(anonymizedRevealedDocument);

      // getIndicies: calculate reveal indicies
      //   compare anonymized statements and anonymized revealed statements
      //   to compute reveal indicies
      const anonymizedStatementsOriginal = documentStatements.map(
        (s: TermwiseStatement) => {
          hiddenUris.forEach((uri, i) => {
            s = s.replace(uri, `did:anon:${i}`);
          });
          return s;
        }
      );
      const anonymizedStatementsToBeVerified = await this.createVerifyDocumentData(
        anonymizedRevealedDocument,
        {
          suite,
          documentLoader,
          expansionMap,
          skipProofCompaction
        }
      );
      let revealIndicies = this.getIndicies(
        anonymizedStatementsOriginal,
        anonymizedStatementsToBeVerified,
        proofStatements
      );
      revealIndiciesArray.push(revealIndicies);

      // calculate index of hidden URIs
      terms.forEach((term, termIndex) => {
        if (equivs.has(term)) {
          if (revealIndicies.includes(termIndex)) {
            let e = equivs.get(term) as [number, number][];
            e.push([index, termIndex]);
          }
        }
      });

      // Fetch the verification method
      const verificationMethod = await this.getVerificationMethod({
        proof,
        document,
        documentLoader,
        expansionMap
      });

      // Construct a key pair class from the returned verification method
      const issuerPublicKey = verificationMethod.publicKeyJwk
        ? await this.LDKeyClass.fromJwk(verificationMethod)
        : await this.LDKeyClass.from(verificationMethod);

      issuerPublicKeyArray.push(issuerPublicKey.publicKeyBuffer);

      // Set the relevant proof elements on the derived proof from the input proof
      derivedProof.verificationMethod = proof.verificationMethod;
      derivedProof.proofPurpose = proof.proofPurpose;
      derivedProof.created = proof.created;
      // Set the nonce on the derived proof
      derivedProof.nonce = Buffer.from(nonce).toString("base64");

      derivedProofs.push(derivedProof);

      index++;
    }

    const equivsArray: [number, number][][] = [...equivs.values()];

    // Compute the proof
    const outputProofs = await blsCreateProofMulti({
      signature: signatureArray.map(signature => new Uint8Array(signature)),
      publicKey: issuerPublicKeyArray.map(
        (issuerPublicKey: Buffer) => new Uint8Array(issuerPublicKey)
      ),
      messages: termsArray,
      nonce: nonce,
      revealed: revealIndiciesArray,
      equivs: equivsArray
    });

    // Set the proof value on the derived proof
    const results = [];
    for (let i = 0; i < revealedDocuments.length; i++) {
      derivedProofs[i].proofValue = Buffer.from(outputProofs[i].value).toString(
        "base64"
      );
      results.push({
        document: revealedDocuments[i],
        proof: derivedProofs[i]
      });
    }

    return results;
  }

  /**
   * @param options {object} options for verifying the proof.
   *
   * @returns {Promise<{object}>} Resolves with the verification result.
   */
  async verifyProofMulti(
    options: VerifyProofMultiOptions
  ): Promise<VerifyProofMultiResult> {
    const { inputDocuments, documentLoader, expansionMap, purpose } = options;

    const messagesArray: Uint8Array[][] = [];
    const proofArray: { value: Uint8Array }[] = [];
    const issuerPublicKeyArray: Uint8Array[] = [];
    const equivs: Map<string, [number, number][]> = new Map();

    let previous_nonce = "";

    try {
      let index = 0;
      for (const { document, proof } of inputDocuments) {
        // TODO: handle the case of empty nonce
        if (proof.nonce !== previous_nonce && previous_nonce !== "") {
          throw new Error(
            "all the nonces in credentials must have the same values"
          );
        }
        previous_nonce = proof.nonce;

        proofArray.push({
          value: new Uint8Array(Buffer.from(proof.proofValue, "base64"))
        });

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
        // e.g., urn:bnid:_:c14n0 -> _:c14n0
        const documentStatements = await this.deskolemize(
          skolemizedDocumentStatements
        );

        // concat proof and document to be verified
        const terms = proofStatements
          .concat(documentStatements)
          .flatMap((item: TermwiseStatement) => item.toTerms());

        messagesArray.push(
          terms.map((term: string) => new Uint8Array(Buffer.from(term)))
        );

        // TODO: extract blinding indicies from anonIDs `did:anon:${id}`
        terms.forEach((term, termIndex) => {
          let found = term.match(/^<did:anon:([0-9]+)>/);
          if (found !== null) {
            if (equivs.has(found[1])) {
              equivs.get(found[1])?.push([index, termIndex]);
            } else {
              equivs.set(found[1], [[index, termIndex]]);
            }
          }
        });

        // Fetch the verification method
        const verificationMethod = await this.getVerificationMethod({
          proof,
          document,
          documentLoader,
          expansionMap
        });

        // Construct a key pair class from the returned verification method
        const key = verificationMethod.publicKeyJwk
          ? await this.LDKeyClass.fromJwk(verificationMethod)
          : await this.LDKeyClass.from(verificationMethod);

        issuerPublicKeyArray.push(new Uint8Array(key.publicKeyBuffer));

        index++;
      }

      const equivsArray: [number, number][][] = [...equivs.entries()]
        .sort()
        .map(e => e[1]);

      // Verify the proof
      const verified = await blsVerifyProofMulti({
        proof: proofArray,
        publicKey: issuerPublicKeyArray,
        messages: messagesArray,
        nonce: new Uint8Array(Buffer.from(previous_nonce as string, "base64")),
        equivs: equivsArray
      });

      // TODO: redefine validation process
      // // Ensure proof was performed for a valid purpose
      // const { valid, error } = await purpose.validate(proof, {
      //   document,
      //   suite: this,
      //   verificationMethod,
      //   documentLoader,
      //   expansionMap
      // });
      // if (!valid) {
      //   throw error;
      // }
      return verified;
    } catch (error) {
      return { verified: false, error };
    }
  }
}
