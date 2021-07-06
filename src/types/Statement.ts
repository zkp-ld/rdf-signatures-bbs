import rdfCanonize from "rdf-canonize";
const NQuads = rdfCanonize.NQuads;

export interface Statement {
  serialize(): Uint8Array[];
  skolemize(): Statement;
}

export class StringStatement implements Statement {
  private readonly buffer: string;

  constructor(str: string) {
    this.buffer = str;
  }

  toString(): string {
    return this.buffer;
  }

  serialize(): Uint8Array[] {
    return [new Uint8Array(Buffer.from(this.buffer))];
  }

  skolemize(): Statement {
    return new StringStatement(
      this.buffer.replace(/(_:c14n[0-9]+)/g, "<urn:bnid:$1>")
    );
  }
}

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
const RDF = "http://www.w3.org/1999/02/22-rdf-syntax-ns#";
const RDF_LANGSTRING = RDF + "langString";
const XSD_STRING = "http://www.w3.org/2001/XMLSchema#string";
const TYPE_NAMED_NODE = "NamedNode";
const TYPE_BLANK_NODE = "BlankNode";

/**
 * Escape string to N-Quads literal
 */
const _escape = (s: string): string => {
  return s.replace(/["\\\n\r]/g, (match): string => {
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

  serialize(): Uint8Array[] {
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

    return [sOut, pOut, oOut, gOut].map(
      term => new Uint8Array(Buffer.from(term))
    );
  }

  skolemize(): Statement {
    // deep copy
    const out: Quad = JSON.parse(JSON.stringify(this.buffer));

    if (out.subject.termType === TYPE_BLANK_NODE) {
      out.subject.value = out.subject.value.replace(
        /(_:c14n[0-9]+)/,
        "<urn:bnid:$1>"
      );
    }

    if (out.object.termType === TYPE_BLANK_NODE) {
      out.object.value = out.object.value.replace(
        /(_:c14n[0-9]+)/,
        "<urn:bnid:$1>"
      );
    }

    if (out.graph?.termType === TYPE_BLANK_NODE) {
      out.graph.value = out.graph.value.replace(
        /(_:c14n[0-9]+)/,
        "<urn:bnid:$1>"
      );
    }

    return new TermwiseStatement(out);
  }
}
