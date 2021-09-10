import { Statement } from "./types";

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

  deskolemize(): Statement {
    return new StringStatement(
      this.buffer.replace(/<urn:bnid:(_:c14n[0-9]+)>/g, "$1")
    );
  }

  replace(from: string, to: string): Statement {
    return new StringStatement(this.buffer.replace(from, to));
  }
}
