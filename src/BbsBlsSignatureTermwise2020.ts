import { BbsBlsSignature2020 } from "./BbsBlsSignature2020";
import { SignatureSuiteOptions } from "./types";
import rdfCanonize from "rdf-canonize";
const NQuads = rdfCanonize.NQuads;

export class BbsBlsSignatureTermwise2020 extends BbsBlsSignature2020 {
  constructor(options: SignatureSuiteOptions) {
    super(options);
  }

  /**
   * @param c14nStatements {string} canonized RDF N-Quads as a string
   *
   * @returns {string[]} a flatten array of [subject, predicate, object, graph]s
   */
  private parseC14nStatements(c14nStatements: string): string[] {
    const rdfStatements = NQuads.parse(c14nStatements);

    // TODO: save object's datatype if any
    return rdfStatements.flatMap((s: any) => [
      s.subject.value,
      s.predicate.value,
      s.object.value,
      s.graph.value
    ]);
  }

  /**
   * @param proof to canonicalize
   * @param options to create verify data
   *
   * @returns {Promise<{string[]>}.
   */
  async createVerifyProofData(
    proof: any,
    { documentLoader, expansionMap }: any
  ): Promise<string[]> {
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
   * @returns {Promise<{string[]>}.
   */
  async createVerifyDocumentData(
    document: any,
    { documentLoader, expansionMap }: any
  ): Promise<string[]> {
    const c14nDocument = await this.canonize(document, {
      documentLoader,
      expansionMap
    });

    return this.parseC14nStatements(c14nDocument);
  }
}
