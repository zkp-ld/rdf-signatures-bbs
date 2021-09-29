/* eslint-disable @typescript-eslint/no-explicit-any */
import { BbsBlsSignature2020 } from "./BbsBlsSignature2020";
import { SignatureSuiteOptions } from "./types";
import { TermwiseStatement } from "./TermwiseStatement";

export class BbsBlsSignatureTermwise2020 extends BbsBlsSignature2020 {
  constructor(options: SignatureSuiteOptions = {}) {
    super(options);
    this.Statement = TermwiseStatement;
  }

  /**
   * @param nQuads {string} canonized RDF N-Quads as a string
   *
   * @returns {TermwiseStatement[]} an array of statements
   */
  getStatements(nQuads: string): TermwiseStatement[] {
    return nQuads
      .split("\n")
      .filter((_) => _.length > 0)
      .map((s: string) => new this.Statement(s));
  }

  /**
   * @param proof to canonicalize
   * @param options to create verify data
   *
   * @returns {Promise<TermwiseStatement[]>}.
   */
  async createVerifyProofData(
    proof: any,
    { documentLoader, expansionMap }: any
  ): Promise<TermwiseStatement[]> {
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
   * @returns {Promise<TermwiseStatement[]>}.
   */
  async createVerifyDocumentData(
    document: any,
    { documentLoader, expansionMap }: any
  ): Promise<TermwiseStatement[]> {
    const c14nDocument = await this.canonize(document, {
      documentLoader,
      expansionMap
    });

    return this.getStatements(c14nDocument);
  }
}
