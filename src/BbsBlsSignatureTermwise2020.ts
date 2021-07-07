/* eslint-disable @typescript-eslint/no-explicit-any */
import { BbsBlsSignature2020 } from "./BbsBlsSignature2020";
import { SignatureSuiteOptions, Statement } from "./types";
import { TermwiseStatement } from "./TermwiseStatement";

export class BbsBlsSignatureTermwise2020 extends BbsBlsSignature2020 {
  constructor(options: SignatureSuiteOptions = {}) {
    super(options);
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
      .map((s: string) => new TermwiseStatement(s));
  }
}
