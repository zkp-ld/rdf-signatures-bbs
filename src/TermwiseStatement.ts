/*
 * The code in this file partially originated from
 * @see https://github.com/digitalbazaar/rdf-canonize
 * Hence the following copyright notice applies
 *
 * Copyright (c) 2016-2021 Digital Bazaar, Inc. All rights reserved.
 */

import rdfCanonize from "rdf-canonize";
const NQuads = rdfCanonize.NQuads;
import { Statement } from "./types";

const RDF = "http://www.w3.org/1999/02/22-rdf-syntax-ns#";
const RDF_LANGSTRING = RDF + "langString";
const XSD_STRING = "http://www.w3.org/2001/XMLSchema#string";
const TYPE_NAMED_NODE = "NamedNode";
const TYPE_BLANK_NODE = "BlankNode";

type Quad = {
  subject: {
    termType: string;
    value: string;
  };
  predicate: {
    termType: string;
    value: string;
  };
  object: {
    termType: string;
    value: string;
    datatype?: {
      termType: string;
      value: string;
    };
    language?: string;
  };
  graph?: {
    termType: string;
    value: string;
  };
};

/**
 * Escape string to N-Quads literal
 */
const _escape = (s: string): string => {
  return s.replace(/["\\\n\r]/g, (match: string): string => {
    switch (match) {
      case '"':
        return '\\"';
      case "\\":
        return "\\\\";
      case "\n":
        return "\\n";
      case "\r":
        return "\\r";
      default:
        return "";
    }
  });
};

export class TermwiseStatement implements Statement {
  private readonly buffer: Quad;

  constructor(terms: string);
  constructor(terms: Quad);
  constructor(terms: string | Quad) {
    if (typeof terms === "string") {
      const rdfStatement = NQuads.parse(terms);
      if (rdfStatement.length < 1) {
        throw Error(
          "Cannot construct TermwiseStatement instance due to incorrect input"
        );
      }
      this.buffer = rdfStatement[0];
    } else {
      this.buffer = terms;
    }
  }

  toString(): string {
    return NQuads.serializeQuad(this.buffer);
  }

  toTerms(): [string, string, string, string] {
    const s = this.buffer.subject;
    const p = this.buffer.predicate;
    const o = this.buffer.object;
    const g = this.buffer.graph;

    // subject can only be NamedNode or BlankNode
    const sOut = s.termType === TYPE_NAMED_NODE ? `<${s.value}>` : `${s.value}`;

    // predicate can only be NamedNode
    const pOut = `<${p.value}>`;

    // object is NamedNode, BlankNode, or Literal
    let oOut = "";
    if (o.termType === TYPE_NAMED_NODE) {
      oOut = `<${o.value}>`;
    } else if (o.termType === TYPE_BLANK_NODE) {
      oOut = o.value;
    } else {
      oOut += `"${_escape(o.value)}"`;
      if (o.datatype?.value === RDF_LANGSTRING) {
        if (o.language) {
          oOut += `@${o.language}`;
        }
      } else if (o.datatype?.value !== XSD_STRING) {
        oOut += `^^<${o.datatype?.value}>`;
      }
    }

    // graph can only be NamedNode or BlankNode (or DefaultGraph, but that
    // does not add to `nquad`)
    let gOut = "";
    if (g?.termType === TYPE_NAMED_NODE) {
      gOut = `<${g.value}>`;
    } else if (g?.termType === TYPE_BLANK_NODE) {
      gOut = `${g.value}`;
    }

    return [sOut, pOut, oOut, gOut];
  }

  serialize(): Uint8Array[] {
    return this.toTerms().map(term => new Uint8Array(Buffer.from(term)));
  }

  skolemize(): Statement {
    // deep copy
    const out: Quad = JSON.parse(JSON.stringify(this.buffer));

    const _skolemize = (x: string): string =>
      x.replace(/(_:c14n[0-9]+)/, "<urn:bnid:$1>");

    if (out.subject.termType === TYPE_BLANK_NODE) {
      out.subject.value = _skolemize(out.subject.value);
    }
    if (out.object.termType === TYPE_BLANK_NODE) {
      out.object.value = _skolemize(out.object.value);
    }
    if (out.graph?.termType === TYPE_BLANK_NODE) {
      out.graph.value = _skolemize(out.graph.value);
    }

    return new TermwiseStatement(out);
  }

  /**
   * Transform the blank node identifier placeholders for the document statements
   * back into actual blank node identifiers
   * e.g., <urn:bnid:_:c14n0> => _:c14n0
   */
  deskolemize(): Statement {
    // deep copy
    const out: Quad = JSON.parse(JSON.stringify(this.buffer));

    const _deskolemize = (y: string): string =>
      y.replace(/<urn:bnid:(_:c14n[0-9]+)>/g, "$1");

    if (out.subject.termType === TYPE_BLANK_NODE) {
      out.subject.value = _deskolemize(out.subject.value);
    }
    if (out.object.termType === TYPE_BLANK_NODE) {
      out.object.value = _deskolemize(out.object.value);
    }
    if (out.graph?.termType === TYPE_BLANK_NODE) {
      out.graph.value = _deskolemize(out.graph.value);
    }

    return new TermwiseStatement(out);
  }

  replace(from: string, to: string): TermwiseStatement {
    const replaced = { ...this.buffer };

    const s = replaced.subject;
    const p = replaced.predicate;
    const o = replaced.object;
    const g = replaced.graph;

    s.value = s.value.replace(from, to);
    p.value = p.value.replace(from, to);
    o.value = o.value.replace(from, to);
    if (g) {
      g.value = g.value.replace(from, to);
    }

    return new TermwiseStatement(replaced);
  }
}
