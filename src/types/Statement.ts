export interface Statement {
  serialize(): Uint8Array[];
  skolemize(): Statement;
  deskolemize(): Statement;
}
