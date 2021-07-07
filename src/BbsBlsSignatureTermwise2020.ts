/* eslint-disable @typescript-eslint/no-explicit-any */
import { BbsBlsSignature2020 } from "./BbsBlsSignature2020";
import { SignatureSuiteOptions, Statement } from "./types";
import { TermwiseStatement } from "./TermwiseStatement";

export class BbsBlsSignatureTermwise2020 extends BbsBlsSignature2020 {
  constructor(options: SignatureSuiteOptions = {}) {
    super(options);
  }

  /**
   * @param c14nStatements {string} canonized RDF N-Quads as a string
   *
   * @returns {string[][]} an array of [subject, predicate, object, graph]s
   */
  private parseC14nStatements(c14nStatements: string): Statement[] {
    return c14nStatements
      .split("\n")
      .filter(_ => _.length > 0)
      .map((s: string) => new TermwiseStatement(s));
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

    return this.parseC14nStatements(c14nProofOptions);
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

    return this.parseC14nStatements(c14nDocument);
  }
}
