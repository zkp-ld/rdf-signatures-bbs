/*
 * Copyright 2020 - MATTR Limited
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

import * as RDF from "@rdfjs/types";

export type TbsTerm = RDF.NamedNode | RDF.BlankNode | RDF.Literal;

/**
 * Options for creating a proof for multiple credentials
 */
export interface DeriveProofMultiRDFOptions {
  /**
   * Input documents, proofs, and reveal documents
   */
  readonly inputDocuments: DeriveProofMultiRDFInputDocs[];
  /**
   * Optional custom document loader
   */
  // eslint-disable-next-line @typescript-eslint/ban-types
  documentLoader?: Function;
  /**
   * Nonce to include in the derived proof
   */
  readonly nonce?: Uint8Array;
}

export interface DeriveProofMultiRDFInputDocs {
  /**
   * Document featuring the proof to derive from
   */
  readonly document: RDF.Quad[];
  /**
   * Proof(s) securing the document
   */
  readonly proofs: RDF.Quad[][];
  /**
   * Derived subset of `document`, i.e., selectively-disclosed and anonymized document
   */
  readonly revealedDocument: RDF.Quad[];
  /**
   * De-anonymization map from anonymous IRI to the original IRIs, blank node ids, and literals
   */
  readonly anonToTerm: Map<string, TbsTerm>;
}
