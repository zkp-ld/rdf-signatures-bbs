/* eslint-disable @typescript-eslint/no-explicit-any */
import { BbsBlsSignature2020 } from "./BbsBlsSignature2020";
import { SignatureSuiteOptions } from "./types";
import { TermwiseStatement } from "./TermwiseStatement";

export class BbsBlsSignatureTermwise2020 extends BbsBlsSignature2020 {
  constructor(options: SignatureSuiteOptions = {}) {
    super(options);
    this.Statement = TermwiseStatement;
  }
}
