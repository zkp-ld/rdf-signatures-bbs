export interface Statement {
  serialize(): Uint8Array[];
  skolemize(): Statement;
  deskolemize(): Statement;
  replace(from: string, to: string): Statement;
}
