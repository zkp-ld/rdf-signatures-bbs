import * as RDF from "@rdfjs/types";

export interface DerivedProof {
  document: RDF.Quad[];
  proofs: RDF.Quad[][];
}
