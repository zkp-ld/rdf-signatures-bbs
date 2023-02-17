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
/**
 * Options for verifying a proof
 */
export interface VerifyProofMultiOptions {
  /**
   * Input documents and proofs to be verified
   */
  readonly inputDocuments: VerifyProofMultiInputDocs[];
  /**
   * The proof purpose to specify for the generated proof
   */
  readonly purpose: any;
  /**
   * Optional custom document loader
   */
  // eslint-disable-next-line @typescript-eslint/ban-types
  documentLoader?: Function;
}

export interface VerifyProofMultiInputDocs {
  /**
   * The proof
   */
  readonly proof: any;
  /**
   * The document
   */
  readonly document: any;
}
