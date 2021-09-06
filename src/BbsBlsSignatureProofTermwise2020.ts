/* eslint-disable @typescript-eslint/no-explicit-any */
import jsonld from "jsonld";
import { SECURITY_CONTEXT_URL } from "jsonld-signatures";
import { BbsBlsSignatureProof2020 } from "./BbsBlsSignatureProof2020";
import { BbsBlsSignatureTermwise2020 } from "./BbsBlsSignatureTermwise2020";
import {
  Statement,
  CanonicalizeOptions,
  TermwiseCanonicalizeResult,
  DeriveProofMultiOptions,
  BBSInput
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
      [...Array(NUM_OF_TERMS_IN_STATEMENT)].map(
        (_, i) => index * NUM_OF_TERMS_IN_STATEMENT + i
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

    const bbsInputs: BBSInput[] = [];
    const revealedDocuments: any = [];
    const derivedProofs: any = [];
    const E = Object.fromEntries(hiddenUris.map(uri => [uri, []]));

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

      // skolemize: name all the blank nodes
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

      revealedDocuments.push(revealedDocument);

      // getIndicies: calculate reveal indicies
      let revealIndicies = this.getIndicies(
        skolemizedDocumentStatements,
        revealedDocumentStatements,
        proofStatements
      );

      // calculate index of hidden URIs
      terms.forEach((term, termIndex) => {
        if (term in E) {
          if (termIndex in revealIndicies) {
            // remove hidden URI from revealIndicies
            revealIndicies = revealIndicies.filter(i => i != termIndex);
            // add (credIndex, termIndex) to E
            E[term].push([index, termIndex]);
          }
        }
      });

      // // FOR DEBUG: output console.log
      // this.logRevealedStatements(
      //   skolemizedDocumentStatements,
      //   proofStatements,
      //   revealedDocumentStatements
      // );

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

      // Set the relevant proof elements on the derived proof from the input proof
      derivedProof.verificationMethod = proof.verificationMethod;
      derivedProof.proofPurpose = proof.proofPurpose;
      derivedProof.created = proof.created;

      // Set the nonce on the derived proof
      derivedProof.nonce = Buffer.from(nonce).toString("base64");

      bbsInputs.push({
        terms,
        revealIndicies,
        issuerPublicKey,
        signature
      });

      derivedProofs.push(derivedProof);

      index++;
    }

    return {};

    // TBD: inputStatements -> msgVkSigs への変換 (各 term へのラベル付けと同値関係 E の計算)

    // // Compute the proof
    // const outputProof = await blsCreateProofMulti({
    //   msgVkSigs,
    //   nonce: nonce,
    // });

    // // Set the proof value on the derived proof
    // const presentationProof = {
    //   proofValue: Buffer.from(outputProof).toString("base64")
    // };

    // return {
    //   document: revealedDocuments,
    //   proof: presentationProof
    // };
  }
}
