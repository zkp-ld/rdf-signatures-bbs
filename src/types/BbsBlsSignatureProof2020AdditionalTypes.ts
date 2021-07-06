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

import { BbsBlsSignature2020 } from "src/BbsBlsSignature2020";
import { Statement } from "./Statement";

/* eslint-disable @typescript-eslint/no-explicit-any */
export interface CanonicalizeOptions {
  /**
   * The signature suite
   */
  readonly suite: BbsBlsSignature2020;
  /**
   * Optional custom document loader
   */
  documentLoader?: Function;
  /**
   * Optional expansion map
   */
  expansionMap?: Function;
  /**
   * Indicates whether to compact the resulting proof
   */
  readonly skipProofCompaction?: boolean;
}

export interface CanonicalizeResult {
  /**
   * document statements (array of quads)
   */
  documentStatements: Statement[];
  /**
   * proof statements (array of quads)
   */
  proofStatements: Statement[];
}

export interface SkolemizeResult {
  /**
   * Skolemized document (JSON-LD)
   */
  skolemizedDocument: string;
  /**
   * Skolemized document (array of quads)
   */
  skolemizedDocumentStatements: Statement[];
}

export interface RevealOptions {
  /**
   * The signature suite
   */
  readonly suite: BbsBlsSignature2020;
  /**
   * Optional custom document loader
   */
  documentLoader?: Function;
  /**
   * Optional expansion map
   */
  expansionMap?: Function;
}

export interface RevealResult {
  /**
   * Revealed document (JSON-LD)
   */
  revealedDocument: any;
  /**
   * Revealed document statements (array of quads)
   */
  revealedDocumentStatements: Statement[];
}
