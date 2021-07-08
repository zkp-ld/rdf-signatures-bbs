/* eslint-disable @typescript-eslint/no-explicit-any */
import { BbsBlsSignatureProof2020 } from "./BbsBlsSignatureProof2020";
import { BbsBlsSignatureTermwise2020 } from "./BbsBlsSignatureTermwise2020";
import { Statement } from "./types";
import { TermwiseStatement } from "./TermwiseStatement";

export class BbsBlsSignatureProofTermwise2020 extends BbsBlsSignatureProof2020 {
  constructor(options: any) {
    super(options);
    this.Suite = BbsBlsSignatureTermwise2020;
    this.Statement = TermwiseStatement;
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
}
