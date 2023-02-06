/* eslint-disable @typescript-eslint/no-explicit-any */
import jsonld from "jsonld";
import { suites } from "jsonld-signatures";
import canonize from "rdf-canonize";
import { DataFactory } from "rdf-data-factory";
import * as RDF from "@rdfjs/types";
import { randomBytes } from "@stablelib/random";
import { v4 as uuidv4 } from "uuid";
import {
  blsCreateProofMulti,
  blsVerifyProofMulti
} from "@zkp-ld/bbs-signatures";
import { Bls12381G2KeyPair } from "@zkp-ld/bls12381-key-pair";

import {
  DidDocumentPublicKey,
  CreateVerifyDataOptions,
  CanonizeOptions,
  CanonicalizeOptions,
  CanonicalizeResult,
  DeriveProofMultiOptions,
  VerifyProofMultiOptions,
  VerifyProofMultiResult,
  DeriveProofOptions,
  VerifyProofOptions,
  VerifyProofResult,
  DeriveProofMultiRDFOptions
} from "./types";
import { BbsTermwiseSignature2021 } from "./BbsTermwiseSignature2021";
import {
  Statement,
  TYPE_NAMED_NODE,
  XSD_INTEGER,
  XSD_STRING
} from "./Statement";
import {
  SECURITY_CONTEXT_URLS,
  NUM_OF_TERMS_IN_STATEMENT,
  KEY_FOR_RANGEPROOF
} from "./utilities";
import { DerivedProof } from "./types/DerivedProof";

const PROOF_VALUE_PREDICATE = "https://w3id.org/security#proofValue";
const VERIFICATION_METHOD_PREDICATE =
  "https://w3id.org/security#verificationMethod";
const NONCE_PREDICATE = "https://w3id.org/security#nonce";
const RDF_TYPE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const RDF_LANGSTRING = "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString";
const SIGNATURE_TYPE = "https://zkp-ld.org/security#BbsTermwiseSignature2021";
const PROOF_TYPE = "https://zkp-ld.org/security#BbsTermwiseSignatureProof2021";
const U8_STRING = 0;
const U8_INTEGER = 1;

class URIAnonymizer {
  private prefix = "urn:anon:";
  private regexp = /^<urn:anon:([^>]+)>/;
  private regexp_url =
    /^<https:\/\/zkp-ld.org\/\.well-known\/genid\/anonymous\/([^>]+)>$/;
  private regexp_literal =
    /^"https:\/\/zkp-ld.org\/\.well-known\/genid\/anonymous\/([^"]+)"/;

  private equivs: Map<string, [string, [number, number][]]> = new Map();

  constructor();
  constructor(equivs: Map<string, [string, [number, number][]]>);
  constructor(equivs?: Map<string, [string, [number, number][]]>) {
    if (equivs) {
      this.equivs = equivs;
    }
  }

  anonymizeJsonld(doc: any): any {
    const anonymizeDocument = (doc: any): void => {
      for (const [k, v] of Object.entries(doc)) {
        if (v != null && typeof v === "object") {
          anonymizeDocument(v);
        } else if (typeof v === "string") {
          const anid = this.equivs.get(`<${v}>`);
          if (anid !== undefined) {
            doc[k] = `${this.prefix}${anid[0]}`;
          }
        }
      }
    };

    const res = { ...doc }; // copy input
    anonymizeDocument(res);
    return res;
  }

  anonymizeStatement(s: Statement): Statement {
    for (const [uri, value] of this.equivs) {
      s = s.replace(uri.slice(1, -1), `${this.prefix}${value[0]}`);
    }
    return s;
  }

  extractAnonID(t: string): string | null {
    const found =
      t.match(this.regexp) ||
      t.match(this.regexp_url) ||
      t.match(this.regexp_literal);
    if (found === null) return null;
    return found[1];
  }
}

export class BbsTermwiseSignatureProof2021 extends suites.LinkedDataProof {
  constructor({ useNativeCanonize, key, LDKeyClass, type }: any = {}) {
    super({
      type: "BbsTermwiseSignatureProof2021"
    });

    this.proof = {
      "@context": SECURITY_CONTEXT_URLS,
      type: "BbsTermwiseSignatureProof2021"
    };

    this.mappedDerivedProofType = "BbsTermwiseSignature2021";
    this.supportedDeriveProofType =
      BbsTermwiseSignatureProof2021.supportedDerivedProofType;
    this.LDKeyClass = LDKeyClass ?? Bls12381G2KeyPair;
    this.proofSignatureKey = "proofValue";
    this.key = key;
    this.useNativeCanonize = useNativeCanonize;
    this.Suite = BbsTermwiseSignature2021;
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
      .filter((_) => _.length > 0)
      .map((s: string) => new Statement(s));
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
  async getVerificationMethod({
    proof,
    documentLoader
  }: any): Promise<DidDocumentPublicKey> {
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
        // adding jws-2020 context to allow publicKeyJwk
        "@context": [
          "https://w3id.org/security/v2",
          "https://w3id.org/security/suites/jws-2020/v1"
        ],
        "@embed": "@always",
        id: verificationMethod
      },
      {
        documentLoader,
        compactToRelative: false,
        expandContext: SECURITY_CONTEXT_URLS
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
    const { suite, documentLoader, expansionMap, skipProofCompaction } =
      options;

    // Get the input document statements
    const documentStatements: Statement[] =
      await suite.createVerifyDocumentData(document, {
        documentLoader,
        expansionMap,
        compactProof: !skipProofCompaction
      });

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
   * Calculate revealed indicies
   *
   * @param fullStatements full document statements
   * @param partialStatements revealed document statements
   *
   * @returns {number[]} revealed statementwise indicies
   */
  getIndicies(
    fullStatements: Statement[],
    partialStatements: Statement[]
  ): number[] {
    // Reveal the statements indicated from the reveal document
    const documentRevealedIndicies = partialStatements.map((x) =>
      fullStatements.findIndex((y) => x.toString() === y.toString())
    );
    if (documentRevealedIndicies.includes(-1)) {
      throw new Error(
        "Some statements in the reveal document not found in original proof"
      );
    }
    // Check there is not a mismatch
    if (documentRevealedIndicies.length !== partialStatements.length) {
      throw new Error(
        "Some statements in the reveal document not found in original proof"
      );
    }
    return documentRevealedIndicies;
  }

  /**
   * Expand indicies to fit termwise encoding
   *   e.g., [0,       2,         5          ]  (statementwise)
   *      -> [0,1,2,3, 8,9,10,11, 20,21,22,23]  (termwise)
   *
   * @param {number[]} statementIndicies statementwise indicies
   *
   * @returns {number[]} termwise indicies
   */
  statementIndiciesToTermIndicies(statementIndicies: number[]): number[] {
    return statementIndicies.flatMap((index) =>
      [...Array(NUM_OF_TERMS_IN_STATEMENT).keys()].map(
        (i) => index * NUM_OF_TERMS_IN_STATEMENT + i
      )
    );
  }

  statementToUint8(statementArray: Statement[][]): Uint8Array {
    return new Uint8Array(
      Buffer.from(
        statementArray
          .map((statements) =>
            statements.map((statement) => statement.toString()).join("")
          )
          .join("")
      )
    );
  }

  /**
   * Identify JSON paths to range indicator in reveal document (JSON-LD frame) such that:
   *   [
   *     [ "https://www.w3.org/2018/credentials#credentialSubject",
   *       "http://schema.org/containsPlace",
   *       "http://schema.org/maximumAttendeeCapacity",
   *       "", 1000, 5000, "http://example.org/townA2" ],
   *     [ "https://www.w3.org/2018/credentials#credentialSubject",
   *       "http://schema.org/maximumAttendeeCapacity",
   *       "", 4000, 6000, "" ]
   *   ]
   *
   * @param frame expanded JSON-LD frame
   * @param path initial path
   * @param parentID "@id" in upper layer if any
   *
   * @returns {(string | number)[][]} JSON paths to range indicator in reveal document (JSON-LD frame)
   */
  getRangePaths(
    frame: any,
    path: (string | number)[] = [],
    parentID = ""
  ): (string | number)[][] {
    const res: (string | number)[][] = [];

    if (!Array.isArray(frame)) return [];

    for (let i = 0; i < frame.length; i++) {
      if (typeof frame[i] !== "object") continue;

      const currentID = "@id" in frame[i] ? frame[i]["@id"] : "";

      for (const [k, v] of Object.entries(frame[i])) {
        if (k === KEY_FOR_RANGEPROOF) {
          if (!Array.isArray(v)) return [];
          // add delimiter to path
          path.push("");
          // add min and max to path
          for (const rv of v) {
            path.push(rv["@value"]);
          }
          // add parent @id to path
          path.push(parentID);
          // add path to response
          res.push(path);
        } else if (Array.isArray(v)) {
          res.push(...this.getRangePaths(v, path.concat(k), currentID));
        }
      }
    }

    return res;
  }

  /**
   * Overwrite range proof indicators to the revealed document to be shown to the verifier
   *
   * @param doc expanded JSON-LD revealed document to be overwritten
   * @param path path to range proof indicators calculated by getRangePaths()
   */
  updateDocWithRange(doc: any, path: (string | number)[]): void {
    if (!Array.isArray(doc) || path[0] === "") return;

    for (let i = 0; i < doc.length; i++) {
      if (typeof doc[i] !== "object") continue;

      for (const [j, v] of Object.entries(doc[i])) {
        if (j === path[0]) {
          if (!Array.isArray(v)) return;

          if (path[1] === "") {
            // overwrite a rangeproof part of the revealed document
            for (let k = 0; k < doc[i][j].length; k++) {
              doc[i][j][k] = {
                [KEY_FOR_RANGEPROOF]: [
                  { "@value": path[2] },
                  { "@value": path[3] }
                ]
              };
            }
          } else {
            this.updateDocWithRange(v, path.slice(1));
          }
        }
      }
    }
  }

  compactRange(doc: any): void {
    if (!Array.isArray(doc)) return;

    for (let i = 0; i < doc.length; i++) {
      if (typeof doc[i] !== "object") continue;

      for (const [k, v] of Object.entries(doc[i])) {
        if (k === KEY_FOR_RANGEPROOF) {
          if (!Array.isArray(v)) return;
          // overwrite a rangeproof part of the revealed document
          doc[i]["@id"] = `${KEY_FOR_RANGEPROOF}${JSON.stringify(
            v.map((vv) => vv["@value"])
          )}`;
          delete doc[i][KEY_FOR_RANGEPROOF];
        } else {
          if (Array.isArray(v)) this.compactRange(v);
        }
      }
    }
  }

  /**
   * Identify term indicies and range to be range-proved
   *
   * @param paths paths to range proof indicators in JSON-LD frame
   * @param anonymizedDocument JSON-LD document
   * @param anonymizedStatements N-Quad statements
   * @param suite
   * @param documentLoader
   * @param expansionMap
   *
   * @returns {Promise<[number, number, number][]>} term-index, min, max to be applied to range proofs
   */
  async getRangeProofIndicies(
    paths: (string | number)[][],
    anonymizedStatements: Statement[],
    suite: any,
    documentLoader: any,
    expansionMap: any
  ): Promise<[number, number, number][]> {
    const pathToFrame = (
      path: (string | number)[]
    ): [any, string, [number, number]] => {
      const frame: any = {
        "@explicit": true
      };
      let pred: string;
      let range: [number, number];
      if (path[1] === "") {
        if (
          typeof path[0] !== "string" ||
          typeof path[2] !== "number" ||
          typeof path[3] !== "number" ||
          typeof path[4] !== "string"
        ) {
          throw new Error("invalid reveal document");
        }
        frame[path[0]] = {};
        pred = path[0];
        range = [path[2], path[3]];
        if (path[4] !== "") frame["@id"] = path[4];
      } else {
        [frame[path[0]], pred, range] = pathToFrame(path.slice(1));
      }
      return [frame, pred, range];
    };

    // construct JSON-LD frames to extract each range-proof part
    const frames = paths.map((path) => pathToFrame(path));

    // reconstruct JSON-LD document for framing
    const anonymizedDocument: string = await jsonld.fromRDF(
      anonymizedStatements.join("\n")
    );

    // extract statements corresponding to range-proof parts using above JSON-LD frames
    return (
      await Promise.all(
        frames.map(
          async ([frame, pred, range]): Promise<[number, number, number][]> => {
            // Frame the result to create the reveal document result
            const revealedDocument = await jsonld.frame(
              anonymizedDocument,
              frame,
              { documentLoader }
            );

            // Canonicalize the resulting reveal document
            const statements: Statement[] =
              await suite.createVerifyDocumentData(revealedDocument, {
                documentLoader,
                expansionMap
              });

            const statementIndicies = this.getIndicies(
              anonymizedStatements,
              statements
                .filter((s) => s.predicate.value === pred)
                .filter((s) => s.object.datatype?.value === XSD_INTEGER)
            );

            return statementIndicies.map((idx) => [
              idx * NUM_OF_TERMS_IN_STATEMENT + 2, // get object term index from statement index
              range[0], // min
              range[1] // max
            ]);
          }
        )
      )
    ).flat();
  }

  /**
   * Derive a proof from a proof and reveal document
   *
   * @param options {object} options for deriving a proof.
   *
   * @returns {Promise<object>} Resolves with the derived proof object.
   */
  // eslint-disable-next-line @typescript-eslint/ban-types
  async deriveProof(options: DeriveProofOptions): Promise<object> {
    const {
      document,
      proof,
      revealDocument,
      documentLoader,
      expansionMap,
      skipProofCompaction,
      nonce,
      hiddenUris
    } = options;

    const derivedProofs = await this.deriveProofMulti({
      inputDocuments: [
        {
          document,
          proof,
          revealDocument
        }
      ],
      documentLoader,
      expansionMap,
      skipProofCompaction,
      nonce,
      hiddenUris
    });

    return derivedProofs[0];
  }

  /**
   * Derive proofs from multiple proofs and reveal documents
   *
   * @param options {object} options for deriving proofs.
   *
   * @returns {Promise<object[]>} Resolves with the array of derived proofs object.
   */
  // eslint-disable-next-line @typescript-eslint/ban-types
  async deriveProofMulti(options: DeriveProofMultiOptions): Promise<object[]> {
    const {
      inputDocuments,
      documentLoader,
      expansionMap,
      skipProofCompaction,
      hiddenUris = [],
      nonce: givenNonce
    } = options;

    // Create a nonce if one is not supplied
    const nonce = givenNonce || randomBytes(50);

    const termsArray: Uint8Array[][] = [];
    const revealedIndiciesArray: number[][] = [];
    const revealedTermIndiciesArray: number[][] = [];
    const issuerPublicKeyArray: Buffer[] = [];
    const signatureArray: Buffer[] = [];
    const revealedDocuments: any = [];
    const derivedProofs: any = [];
    const revealedStatementsArray: Statement[][] = [];
    const rangeProofIndiciesArray: [number, number, number][][] = [];

    const equivs: Map<string, [string, [number, number][]]> = new Map(
      hiddenUris.map((uri) => [`<${uri}>`, [uuidv4(), []]])
    );

    const anonymizer = new URIAnonymizer(equivs);

    const numberOfProofs: number[] = inputDocuments.map(
      ({ proof: givenProof }) =>
        Array.isArray(givenProof) ? givenProof.length : 1
    );
    const proofIndexOffset: number[] = numberOfProofs.map((_, i) =>
      numberOfProofs.slice(0, i).reduce((a, b) => a + b, 0)
    );

    let docIndex = 0;
    for (const {
      document,
      proof: givenProof,
      revealDocument
    } of inputDocuments) {
      // make array from (array | object)
      const proofs = Array.isArray(givenProof) ? givenProof : [givenProof];

      // Initialize the signature suite
      const suite = new this.Suite();

      // Canonicalize: get N-Quads from JSON-LD
      const documentStatements: Statement[] =
        await suite.createVerifyDocumentData(document, {
          documentLoader,
          expansionMap,
          compactProof: !skipProofCompaction
        });

      // Skolemize: transform any blank node identifiers for the input
      // document statements into actual node identifiers
      // e.g., _:c14n0 -> urn:bnid:<docIndex>:_:c14n0
      // where <docIndex> corresponds to the index of document in inputDocuments array
      const skolemizedStatements = documentStatements.map((statement) =>
        statement.skolemize(docIndex)
      );
      const skolemizedDocument: string = await jsonld.fromRDF(
        skolemizedStatements.join("\n")
      );

      // Prepare an equivalence class (equivs) for each blank node identifier
      new Set(
        skolemizedStatements
          .flatMap((item: Statement) => item.toTerms())
          .filter((term) => term.match(/^<urn:bnid:[0-9]+:_:c14n[0-9]+>$/))
      ).forEach((skolemizedBnid) => {
        equivs.set(skolemizedBnid, [uuidv4(), []]);
      });

      // Reveal: extract revealed parts using JSON-LD Framing
      const expandedRevealedDocument = await jsonld.expand(
        anonymizer.anonymizeJsonld(
          await jsonld.frame(skolemizedDocument, revealDocument, {
            documentLoader
          })
        ),
        {
          documentLoader
        }
      );
      const pathsToRanges = this.getRangePaths(
        await jsonld.expand(revealDocument, {
          documentLoader
        })
      );
      if (pathsToRanges.length > 0) {
        pathsToRanges.map((path) =>
          this.updateDocWithRange(expandedRevealedDocument, path)
        );
      }
      const revealedDocument = await jsonld.compact(
        expandedRevealedDocument,
        revealDocument["@context"],
        {
          documentLoader,
          expansionMap,
          compactToRelative: false
        }
      );
      revealedDocuments.push(revealedDocument);

      // Prepare anonymized statements
      const anonymizedStatements = skolemizedStatements.map((statement) =>
        anonymizer.anonymizeStatement(statement)
      );

      // Get range-proved term indicies
      const rangeProofIndicies = await this.getRangeProofIndicies(
        pathsToRanges,
        anonymizedStatements,
        suite,
        documentLoader,
        expansionMap
      );

      // Update anonymized statements using range proof indicators
      for (const [idx, min, max] of rangeProofIndicies) {
        const statementIdx = (idx - 2) / NUM_OF_TERMS_IN_STATEMENT;
        anonymizedStatements[
          statementIdx
        ].object.value = `${KEY_FOR_RANGEPROOF}${JSON.stringify([min, max])}`;
        anonymizedStatements[statementIdx].object.termType = TYPE_NAMED_NODE;
      }

      // Prepare revealed statements: N-Quads revealed statements to be verified by verifier
      // where each specified URI and bnid is replaced by anonymous ID, i.e., urn:anon:<UUIDv4>
      this.compactRange(expandedRevealedDocument); // update
      const revealedStatements = await this.createVerifyDocumentData(
        expandedRevealedDocument,
        {
          suite,
          documentLoader,
          expansionMap,
          skipProofCompaction
        }
      );
      revealedStatementsArray.push(revealedStatements); // for challenge hash

      // Get revealed indicies by comparing two statements
      const preRevealedIndicies = this.getIndicies(
        anonymizedStatements,
        revealedStatements
      );

      // Proof-wise processes
      let proofIndex = 0;
      for (const proof of proofs) {
        // Validate that the input proof document has a proof compatible with this suite
        if (
          !BbsTermwiseSignatureProof2021.supportedDerivedProofType.includes(
            proof.type
          )
        ) {
          throw new TypeError(
            `incompatible proof type: expected proof types of ${JSON.stringify(
              BbsTermwiseSignatureProof2021.supportedDerivedProofType
            )} received ${proof.type}`
          );
        }

        // Extract the original BBS signature from the input proof
        const signature = Buffer.from(proof[this.proofSignatureKey], "base64");
        signatureArray.push(signature);

        // Canonicalize proof: get N-Quads from JSON-LD
        const proofStatements: Statement[] = await suite.createVerifyProofData(
          proof,
          {
            documentLoader,
            expansionMap,
            compactProof: !skipProofCompaction
          }
        );

        // Concat proof and document to get terms to be signed
        const statements = proofStatements.concat(documentStatements);
        termsArray.push(statements.flatMap((s) => s.serialize()));

        // Finalize revealed indicies
        const revealedIndicies = Array.from(
          Array(proofStatements.length).keys()
        ).concat(
          preRevealedIndicies.map((idx) => idx + proofStatements.length)
        );
        revealedIndiciesArray.push(revealedIndicies);

        // Calculate revealed term indicies
        //   to be input to blsCreateProof to generate zkproof
        const revealedTermIndicies =
          this.statementIndiciesToTermIndicies(revealedIndicies);
        revealedTermIndiciesArray.push(revealedTermIndicies);

        // Push each term index of hidden URIs that are not removed by revealing process (JSON-LD framing)
        // to equivalence class
        proofStatements
          .concat(skolemizedStatements)
          .flatMap((statement) => statement.toTerms())
          .forEach((term, termIndex) => {
            if (equivs.has(term) && revealedTermIndicies.includes(termIndex)) {
              const e = equivs.get(term) as [string, [number, number][]];
              e[1].push([proofIndex + proofIndexOffset[docIndex], termIndex]);
            }
          });

        // Add proof statements length to rangeproof indicies
        rangeProofIndiciesArray.push(
          rangeProofIndicies
            .map(([idx, min, max]): [number, number, number] => [
              idx + proofStatements.length * NUM_OF_TERMS_IN_STATEMENT,
              min,
              max
            ])
            .filter(([idx]) => revealedTermIndicies.includes(idx))
        );

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

        // Initialize the derived proof
        let derivedProof;
        if (this.proof) {
          // use proof JSON-LD document passed to API
          derivedProof = await jsonld.compact(
            this.proof,
            SECURITY_CONTEXT_URLS,
            {
              documentLoader,
              expansionMap,
              compactToRelative: false
            }
          );
        } else {
          // Create proof JSON-LD document
          derivedProof = { "@context": SECURITY_CONTEXT_URLS };
        }
        // Ensure proof type is set
        derivedProof.type = this.type;
        // Set the relevant proof elements on the derived proof from the input proof
        derivedProof.verificationMethod = proof.verificationMethod;
        derivedProof.proofPurpose = proof.proofPurpose;
        derivedProof.created = proof.created;
        // Set the nonce on the derived proof
        derivedProof.nonce = Buffer.from(nonce).toString("base64");
        // Embed the revealed statement indicies into the head of proofValue
        derivedProof.proofValue =
          Buffer.from(JSON.stringify(revealedIndicies)).toString("base64") +
          ".";
        derivedProofs.push(derivedProof);

        proofIndex++;
      }

      docIndex++;
    }

    const equivsArray: [number, number][][] = [...equivs.values()].map(
      (v) => v[1]
    );

    // merge revealed statements into nonce (should be separated as claims?)
    const revealedStatementsByte = this.statementToUint8(
      revealedStatementsArray
    );
    const mergedNonce = new Uint8Array(
      nonce.length + revealedStatementsByte.length
    );
    mergedNonce.set(nonce);
    mergedNonce.set(revealedStatementsByte, nonce.length);

    // Compute the proof
    const derivedProofValues = await blsCreateProofMulti({
      signature: signatureArray.map((signature) => new Uint8Array(signature)),
      publicKey: issuerPublicKeyArray.map(
        (issuerPublicKey: Buffer) => new Uint8Array(issuerPublicKey)
      ),
      messages: termsArray,
      nonce: mergedNonce,
      revealed: revealedTermIndiciesArray,
      equivs: equivsArray,
      range: rangeProofIndiciesArray
    });

    // Set the proof value on the derived proof
    const results = [];
    for (const numberOfProof of numberOfProofs) {
      const revealedDocument = revealedDocuments.shift();
      const derivedProofsPerDoc = [];

      for (let _ = 0; _ < numberOfProof; _++) {
        const derivedProof = derivedProofs.shift();
        const derivedProofValue = derivedProofValues.shift();
        if (!derivedProofValue) {
          throw new Error(
            "invalid proofValue generated by blsCreateProofMulti"
          );
        }
        derivedProof.proofValue +=
          Buffer.from(derivedProofValue).toString("base64");
        derivedProofsPerDoc.push(derivedProof);
      }

      results.push({
        document: revealedDocument,
        proof:
          derivedProofsPerDoc.length === 1
            ? derivedProofsPerDoc[0]
            : derivedProofsPerDoc
      });
    }

    return results;
  }

  /**
   * @param options {object} options for verifying the proof.
   *
   * @returns {Promise<{object}>} Resolves with the verification result.
   */
  async verifyProof(options: VerifyProofOptions): Promise<VerifyProofResult> {
    const { document, documentLoader, expansionMap, purpose, proof } = options;

    const result = await this.verifyProofMulti({
      inputDocuments: [
        {
          document,
          proof
        }
      ],
      documentLoader,
      expansionMap,
      purpose
    });

    if (result.results) {
      return result.results[0];
    } else {
      return { verified: result.verified, error: result.error };
    }
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
    const proofArray: Uint8Array[] = [];
    const issuerPublicKeyArray: Uint8Array[] = [];
    const equivs: Map<string, [number, number][]> = new Map();
    const revealedStatementsArray: Statement[][] = [];
    const revealedTermIndiciesArray: number[][] = [];
    const rangeProofIndiciesArray: [number, number, number][][] = [];

    const anonymizer = new URIAnonymizer();

    const numberOfProofs: number[] = inputDocuments.map(
      ({ proof: givenProof }) =>
        Array.isArray(givenProof) ? givenProof.length : 1
    );
    const proofIndexOffset: number[] = numberOfProofs.map((_, i) =>
      numberOfProofs.slice(0, i).reduce((a, b) => a + b, 0)
    );

    let previous_nonce: string | undefined;

    try {
      let docIndex = 0;
      for (const { document, proof: givenProof } of inputDocuments) {
        // make array from (array | object)
        const proofs = Array.isArray(givenProof) ? givenProof : [givenProof];

        // Empty proofs should be rejected
        if (proofs.length === 0) {
          throw new Error(
            "documents to be verified must have at least one proof"
          );
        }

        // Extract and convert range proof indicators
        const expandedDocument = await jsonld.expand(document, {
          documentLoader
        });
        this.compactRange(expandedDocument);

        // Canonicalize document: get N-Quads from JSON-LD
        const revealedStatements: Statement[] =
          await this.createVerifyDocumentData(expandedDocument, {
            documentLoader,
            expansionMap
          });
        // keep document N-Quads statements to calculate challenge hash later
        revealedStatementsArray.push(revealedStatements);

        // Process multiple proofs in an input document
        let proofIndex = 0;
        for (const proof of proofs) {
          if (previous_nonce && proof.nonce !== previous_nonce) {
            throw new Error("all of the nonces must have the same values");
          }
          previous_nonce = proof.nonce;

          // Validate that the input proof document has a proof compatible with this suite
          if (!BbsTermwiseSignatureProof2021.proofType.includes(proof.type)) {
            throw new TypeError(
              `incompatible proof type: expected proof types of ${JSON.stringify(
                BbsTermwiseSignatureProof2021.proofType
              )} received ${proof.type}`
            );
          }

          // Extract revealed indicies and zkproof from proofValue
          const [revealedStatementIndiciesEncoded, proofValue] =
            proof.proofValue.split(".");

          if (
            typeof revealedStatementIndiciesEncoded === "undefined" ||
            typeof proofValue === "undefined"
          ) {
            throw new Error("invalid proofValue");
          }

          let revealedStatementIndicies: number[] = [];
          try {
            revealedStatementIndicies = JSON.parse(
              Buffer.from(revealedStatementIndiciesEncoded, "base64").toString()
            );
          } catch (e) {
            throw new Error("invalid proofValue");
          }

          proofArray.push(new Uint8Array(Buffer.from(proofValue, "base64")));

          // Revert proof.type from BbsTermwiseSignatureProof2021 to BbsTermwiseSignature2021 for verification
          proof.type = this.mappedDerivedProofType;

          // Canonicalize proof: get N-Quads from JSON-LD
          const proofStatements: Statement[] = await this.createVerifyProofData(
            proof,
            {
              documentLoader,
              expansionMap
            }
          );

          // obtain termwise indicies
          const revealedTermIndicies = this.statementIndiciesToTermIndicies(
            revealedStatementIndicies
          ).sort((a, b) => a - b);
          revealedTermIndiciesArray.push(revealedTermIndicies);

          // Reorder statements
          const statements = proofStatements.concat(revealedStatements);
          const reorderedStatements = revealedStatementIndicies
            .map<[number, Statement]>((termIndex, origIndex) => [
              termIndex,
              statements[origIndex]
            ])
            .sort(([termIndexA], [termIndexB]) => termIndexA - termIndexB)
            .map(([, statement]) => statement);
          messagesArray.push(reorderedStatements.flatMap((s) => s.serialize()));

          const terms = reorderedStatements.flatMap((s) => s.toTerms());

          // extract blinding indicies from anonIDs
          terms.forEach((term, termIndex) => {
            const found = anonymizer.extractAnonID(term);
            if (found !== null) {
              if (equivs.has(found)) {
                equivs
                  .get(found)
                  ?.push([
                    proofIndex + proofIndexOffset[docIndex],
                    revealedTermIndicies[termIndex]
                  ]);
              } else {
                equivs.set(found, [
                  [
                    proofIndex + proofIndexOffset[docIndex],
                    revealedTermIndicies[termIndex]
                  ]
                ]);
              }
            }
          });

          // extract range proof indicators
          const rangeProofIndicies: [number, number, number][] = terms
            .map((term, termIndex): [string, number] => [term, termIndex])
            .filter(([term]) => term.startsWith(`<${KEY_FOR_RANGEPROOF}`))
            .map(([term, termIndex]) => {
              const matched = term
                .slice(KEY_FOR_RANGEPROOF.length + 1)
                .match(/(\[|\() *(\d*) *, *(\d*) *(\]|\))/);
              if (!matched || matched.length < 5) {
                throw new Error("invalid range proofs");
              }
              const min_eq = matched[1] === "[";
              const min = parseInt(matched[2]);
              const max = parseInt(matched[3]);
              const max_eq = matched[4] === "]";
              const originalIndex = revealedTermIndicies[termIndex];
              return [originalIndex, min, max];
            });
          rangeProofIndiciesArray.push(rangeProofIndicies);

          // Fetch the verification method
          const verificationMethod = await this.getVerificationMethod({
            proof,
            document,
            documentLoader,
            expansionMap
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

          // Construct a key pair class from the returned verification method
          const key = verificationMethod.publicKeyJwk
            ? await this.LDKeyClass.fromJwk(verificationMethod)
            : await this.LDKeyClass.from(verificationMethod);

          issuerPublicKeyArray.push(new Uint8Array(key.publicKeyBuffer));

          proofIndex++;
        }

        docIndex++;
      }

      const equivsArray: [number, number][][] = [...equivs.entries()]
        .sort()
        .map((e) => e[1]);

      // merge revealed statements into nonce (should be separated as claims?)
      const revealedStatementsByte = this.statementToUint8(
        revealedStatementsArray
      );
      const nonce = new Uint8Array(
        Buffer.from(previous_nonce as string, "base64")
      );
      const mergedNonce = new Uint8Array(
        nonce.length + revealedStatementsByte.length
      );
      mergedNonce.set(nonce);
      mergedNonce.set(revealedStatementsByte, nonce.length);

      // Verify the proof
      const verified = await blsVerifyProofMulti({
        proof: proofArray,
        publicKey: issuerPublicKeyArray,
        messages: messagesArray,
        nonce: mergedNonce,
        revealed: revealedTermIndiciesArray,
        equivs: equivsArray,
        range: rangeProofIndiciesArray
      });

      return verified;
    } catch (error: any) {
      return { verified: false, error };
    }
  }

  static proofType = [
    "BbsTermwiseSignatureProof2021",
    "https://zkp-ld.org/security#BbsTermwiseSignatureProof2021"
  ];

  static supportedDerivedProofType = [
    "BbsTermwiseSignature2021",
    "https://zkp-ld.org/security#BbsTermwiseSignature2021"
  ];

  /**
   * Derive proofs from multiple proofs and reveal documents
   *
   * @param options {object} options for deriving proofs.
   *
   * @returns {Promise<object[]>} Resolves with the array of derived proofs object.
   */
  // eslint-disable-next-line @typescript-eslint/ban-types
  async deriveProofMultiRDF(
    options: DeriveProofMultiRDFOptions
  ): Promise<DerivedProof[]> {
    const { inputDocuments, documentLoader, nonce: givenNonce } = options;

    const rdfdf = new DataFactory();

    // Create a nonce if one is not supplied
    const nonce = givenNonce || randomBytes(50);

    const termsArray: Uint8Array[][] = [];
    const revealedTermIndiciesArray: number[][] = [];
    const issuerPublicKeyArray: Buffer[] = [];
    const signatureArray: Buffer[] = [];
    const revealedDocuments: RDF.Quad[][] = [];
    const preDerivedProofs: RDF.Quad[][] = [];
    const canonicalizedRevealedStatementsNQuadsArrayForNonceExtension: string[] =
      [];
    const rangeProofIndiciesArray: [number, number, number][][] = [];

    const equivs = new Map<string, [number, number][]>();

    const numberOfProofs: number[] = inputDocuments.map(
      ({ proofs }) => proofs.length
    );

    const proofIndexOffset: number[] = numberOfProofs.map((_, i) =>
      numberOfProofs.slice(0, i).reduce((a, b) => a + b, 0)
    );

    let docIndex = 0;
    for (const {
      document,
      proofs,
      revealedDocument,
      anonToTerm
    } of inputDocuments) {
      // Ensure that the revealed document is a derived subset of the document
      // TBD

      // store revealed document to be given into Fiat-Shamir hash calculation below
      revealedDocuments.push(revealedDocument);

      // Add anon IDs in the revealed document to equivs map
      for (const anon of anonToTerm.keys()) {
        if (!equivs.has(anon)) {
          equivs.set(anon, []);
        }
      }

      // Canonicalize the document
      const {
        dataset: canonicalizedDocumentNQuads,
        blankToCanon
      }: {
        dataset: string;
        blankToCanon: Map<string, string>;
      } = await canonize.canonize(document, {
        algorithm: "URDNA2015",
        withMap: true
      });

      // Canonicalize the revealed document
      const canonicalizedRevealedDocumentNQuads: string =
        await canonize.canonize(revealedDocument, {
          algorithm: "URDNA2015"
        });
      const canonicalizedRevealedDocument: RDF.Quad[] = canonize.NQuads.parse(
        canonicalizedRevealedDocumentNQuads
      );

      // Compose anonToTerm and blankToCanon maps
      const anonToCanon = new Map(
        [...anonToTerm.entries()].map(([anon, term]) => [
          anon,
          term.termType === "BlankNode"
            ? rdfdf.blankNode(blankToCanon.get(term.value))
            : term
        ])
      );

      // De-anonymize the canonicalized revealed document using anonToCanon map
      const deAnonymizedCanonicalizedRevealedDocument = [
        ...canonicalizedRevealedDocument
      ].map((quad) => {
        const subject = anonToCanon.get(quad.subject.value) ?? quad.subject;
        const predicate =
          anonToCanon.get(quad.predicate.value) ?? quad.predicate;
        const object = anonToCanon.get(quad.object.value) ?? quad.object;
        const graph = anonToCanon.get(quad.graph.value) ?? quad.graph;
        if (
          subject.termType === "Literal" ||
          predicate.termType === "BlankNode" ||
          predicate.termType === "Literal" ||
          graph.termType === "Literal"
        ) {
          throw new Error("invalid anonToTerm map");
        }
        return rdfdf.quad(subject, predicate, object, graph);
      });

      // Serialize and sort documents
      const deAnonymizedCanonicalizedRevealedDocumentNQuads: string =
        canonize.NQuads.serialize(deAnonymizedCanonicalizedRevealedDocument, {
          sorted: false
        });

      // Get revealed indicies,
      // i.e., statement-wise index mapping
      // from the de-anonymized and canonicalized revealed document
      // to the canonicalized document
      // without counting proof statements yet (so has **pre** as its name)
      const canonicalizedDocumentNQuadArray = canonicalizedDocumentNQuads
        .split("\n")
        .filter((q) => q !== "");
      const deAnonymizedCanonicalizedRevealedDocumentNQuadArray =
        deAnonymizedCanonicalizedRevealedDocumentNQuads
          .split("\n")
          .filter((q) => q !== "");
      const preRevealedIndicies =
        deAnonymizedCanonicalizedRevealedDocumentNQuadArray.map((anon) =>
          canonicalizedDocumentNQuadArray.findIndex((c14n) => anon === c14n)
        );

      // Proof-wise processes
      let proofIndex = 0;
      for (const proof of proofs) {
        // Validate that the input proof document has a proof compatible with this suite
        const proofIdAndType = proof.find(
          (quad) => quad.predicate.value === RDF_TYPE
        );
        if (proofIdAndType == undefined) {
          throw new Error("missing proof.type");
        }
        const { subject: proofId, object: proofType } = proofIdAndType;
        if (
          !BbsTermwiseSignatureProof2021.supportedDerivedProofType.includes(
            proofType.value
          )
        ) {
          throw new TypeError(
            `incompatible proof type: expected proof types of ${JSON.stringify(
              BbsTermwiseSignatureProof2021.supportedDerivedProofType
            )} received ${proofType.value}`
          );
        }

        // Extract the original BBS signature from the input proof
        const proofValue = proof.find(
          (quad) => quad.predicate.value === PROOF_VALUE_PREDICATE
        )?.object;
        if (proofValue == undefined) {
          throw new Error("missing proof.proofValue");
        }
        const signature = Buffer.from(proofValue.value, "base64");
        signatureArray.push(signature);

        // Canonicalize, serialize, and sort proof
        const proofTBS = proof
          .filter(
            (quad) =>
              quad.predicate.value !== PROOF_VALUE_PREDICATE &&
              quad.predicate.value !== NONCE_PREDICATE
          )
          .map((quad) => rdfdf.quad(quad.subject, quad.predicate, quad.object)); // remove graph name
        const canonicalizedProofNQuads: string = await canonize.canonize(
          proofTBS,
          {
            algorithm: "URDNA2015",
            format: "application/nquads"
          }
        );

        // Concat proof and document to get terms to be signed
        const statementsNQuads = [
          canonicalizedProofNQuads,
          canonicalizedDocumentNQuads
        ].join("\n");
        const statements: RDF.Quad[] = canonize.NQuads.parse(statementsNQuads);
        const terms = statements.flatMap((quad) => {
          /**
           * Escape string to N-Quads literal
           * (from rdf-canonize/NQuads.js)
           */
          const _escape = (s: string): string => {
            return s.replace(/["\\\n\r]/g, (match: string) => {
              switch (match) {
                case '"':
                  return '\\"';
                case "\\":
                  return "\\\\";
                case "\n":
                  return "\\n";
                case "\r":
                  return "\\r";
              }
              return match;
            });
          };

          // subject
          const subjectValue =
            quad.subject.termType === "NamedNode"
              ? `<${quad.subject.value}>`
              : quad.subject.value;
          const subject = new Uint8Array([
            U8_STRING, // shows that this array encodes string
            ...Buffer.from(subjectValue)
          ]);

          // predicate
          const predicateValue = `<${quad.predicate.value}>`;
          const predicate = new Uint8Array([
            U8_STRING, // shows that this array encodes string
            ...Buffer.from(predicateValue)
          ]);

          // object
          let object;
          if (
            quad.object.termType === "Literal" &&
            quad.object.datatype.value === XSD_INTEGER
          ) {
            const num = parseInt(quad.object.value);
            if (Number.isSafeInteger(num) && Math.abs(num) < 2 ** 31) {
              object = Uint8Array.of(
                U8_INTEGER, // shows that this array encodes 32-bit integer (big endian)
                (num & 0xff000000) >> 24,
                (num & 0x00ff0000) >> 16,
                (num & 0x0000ff00) >> 8,
                (num & 0x000000ff) >> 0
              );
            } else {
              throw new Error(`integer must be **safe** integer`);
            }
          } else {
            let objectValue;
            if (quad.object.termType === "NamedNode") {
              objectValue = `<${quad.object.value}>`;
            } else if (quad.object.termType === "BlankNode") {
              objectValue = quad.object.value;
            } else if (quad.object.termType === "Literal") {
              objectValue = `"${_escape(quad.object.value)}"`;
              if (quad.object.datatype.value === RDF_LANGSTRING) {
                if (quad.object.language) {
                  objectValue += `@${quad.object.language}`;
                }
              } else if (quad.object.datatype.value !== XSD_STRING) {
                objectValue += `^^<${quad.object.datatype.value}>`;
              }
            } else {
              throw new Error(
                `invalid term type of ${quad.object.value}: ${quad.object.termType}`
              );
            }
            object = new Uint8Array([
              U8_STRING, // shows that this array encodes string
              ...Buffer.from(objectValue)
            ]);
          }

          // graph
          const graphValue =
            quad.graph.termType === "NamedNode"
              ? `<${quad.graph.value}>`
              : quad.graph.value;
          const graph = new Uint8Array([
            U8_STRING, // shows that this array encodes string
            ...Buffer.from(graphValue)
          ]);

          return [subject, predicate, object, graph];
        });
        termsArray.push(terms);

        // Finalize revealed indicies,
        // i.e., statement-wise index mapping
        // from the de-anonymized and canonicalized revealed document
        // to the canonicalized document
        const revealedIndicies = Array.from(
          Array(proofTBS.length).keys()
        ).concat(preRevealedIndicies.map((idx) => idx + proofTBS.length));

        // Calculate revealed term indicies
        //   to be input to blsCreateProof to generate zkproof
        const revealedTermIndicies =
          this.statementIndiciesToTermIndicies(revealedIndicies);
        revealedTermIndiciesArray.push(revealedTermIndicies);

        // Calculate canonicalized revealed statements
        // (= proof + canonicalized revealed document)
        const canonicalizedRevealedStatementsNQuads = [
          canonicalizedProofNQuads,
          canonicalizedRevealedDocumentNQuads
        ].join("\n");
        const canonicalizedRevealedStatements: RDF.Quad[] =
          canonize.NQuads.parse(canonicalizedRevealedStatementsNQuads);

        // store document n-quads for extended nonce
        canonicalizedRevealedStatementsNQuadsArrayForNonceExtension.push(
          canonicalizedRevealedDocumentNQuads
        );

        // Push each anonymized term index with its credential index to equivs map
        canonicalizedRevealedStatements
          .flatMap((q) => [q.subject, q.predicate, q.object, q.graph])
          .forEach((term, termIndex) => {
            if (equivs.has(term.value)) {
              const e = equivs.get(term.value) as [number, number][];
              const credIndex = proofIndex + proofIndexOffset[docIndex];
              const credTermIndex = revealedTermIndicies[termIndex];
              e.push([credIndex, credTermIndex]);
            }
          });

        // TBD: Add proof statements length to rangeproof indicies
        rangeProofIndiciesArray.push([]);

        // Fetch the verification method
        const verificationMethodId = proof.find(
          (quad) => quad.predicate.value === VERIFICATION_METHOD_PREDICATE
        )?.object.value;
        if (verificationMethodId == undefined) {
          throw new Error("missing proof.verificationMethod");
        }
        const verificationMethod = await this.getVerificationMethod({
          proof: {
            verificationMethod: verificationMethodId
          },
          documentLoader
        });

        // Construct a key pair class from the returned verification method
        const issuerPublicKey = verificationMethod.publicKeyJwk
          ? await this.LDKeyClass.fromJwk(verificationMethod)
          : await this.LDKeyClass.from(verificationMethod);
        issuerPublicKeyArray.push(issuerPublicKey.publicKeyBuffer);

        // Initialize the derived proof
        const preDerivedProof: RDF.Quad[] = proofTBS.filter(
          (quad) =>
            !(
              quad.predicate.value === RDF_TYPE &&
              quad.object.value === SIGNATURE_TYPE
            )
        );
        // Ensure proof type is set
        preDerivedProof.push(
          rdfdf.quad(
            proofId,
            rdfdf.namedNode(RDF_TYPE),
            rdfdf.namedNode(PROOF_TYPE)
          )
        );
        // Set the nonce on the derived proof
        preDerivedProof.push(
          rdfdf.quad(
            proofId,
            rdfdf.namedNode(NONCE_PREDICATE),
            rdfdf.literal(Buffer.from(nonce).toString("base64"))
          )
        );
        // Embed the revealed statement indicies into the head of proofValue
        preDerivedProof.push(
          rdfdf.quad(
            proofId,
            rdfdf.namedNode(PROOF_VALUE_PREDICATE),
            rdfdf.literal(
              Buffer.from(JSON.stringify(revealedIndicies)).toString("base64") +
                "."
            )
          )
        );
        preDerivedProofs.push(preDerivedProof);

        proofIndex++;
      }

      docIndex++;
    }

    const equivsArray: [number, number][][] = [...equivs.values()];

    // merge revealed statements into nonce (should be separated as claims?)
    const revealedStatementsByte = new Uint8Array(
      Buffer.from(
        canonicalizedRevealedStatementsNQuadsArrayForNonceExtension.join("")
      )
    );
    const mergedNonce = new Uint8Array(
      nonce.length + revealedStatementsByte.length
    );
    mergedNonce.set(nonce);
    mergedNonce.set(revealedStatementsByte, nonce.length);

    // Compute the proof
    const bbsDerivedProofValues = await blsCreateProofMulti({
      signature: signatureArray.map((signature) => new Uint8Array(signature)),
      publicKey: issuerPublicKeyArray.map(
        (issuerPublicKey: Buffer) => new Uint8Array(issuerPublicKey)
      ),
      messages: termsArray,
      nonce: mergedNonce,
      revealed: revealedTermIndiciesArray,
      equivs: equivsArray,
      range: rangeProofIndiciesArray
    });

    // Set the proof value on the derived proof
    const results: DerivedProof[] = [];
    for (const numberOfProof of numberOfProofs) {
      const revealedDocument = revealedDocuments.shift();
      if (revealedDocument == null) {
        throw new Error("internal error"); // FIXME
      }
      const derivedProofs = [];

      for (let _ = 0; _ < numberOfProof; _++) {
        const preDerivedProof = preDerivedProofs.shift();
        const bbsDerivedProofValue = bbsDerivedProofValues.shift();
        if (preDerivedProof == undefined || bbsDerivedProofValue == undefined) {
          throw new Error(
            "invalid proofValue generated by blsCreateProofMulti"
          );
        }
        const preDerivedProofIdAndValue = preDerivedProof.find(
          (quad) => quad.predicate.value === PROOF_VALUE_PREDICATE
        );
        if (preDerivedProofIdAndValue == undefined) {
          throw new Error("invalid derived proof");
        }
        const { subject: preDerivedProofId, object: preDerivedProofValue } =
          preDerivedProofIdAndValue;

        const derivedProofValue =
          preDerivedProofValue.value +
          Buffer.from(bbsDerivedProofValue).toString("base64");
        const derivedProof = preDerivedProof.filter(
          (quad) => !(quad.predicate.value === PROOF_VALUE_PREDICATE)
        );
        derivedProof.push(
          rdfdf.quad(
            preDerivedProofId,
            rdfdf.namedNode(PROOF_VALUE_PREDICATE),
            rdfdf.literal(derivedProofValue)
          )
        );

        derivedProofs.push(derivedProof);
      }

      results.push({
        document: revealedDocument,
        proofs: derivedProofs
      });
    }

    return results;
  }
}
