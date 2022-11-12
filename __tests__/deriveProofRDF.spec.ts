import jsigs from "jsonld-signatures";
import * as RDF from "@rdfjs/types";
import canonize from "rdf-canonize";
import { DataFactory } from "rdf-data-factory";

import {
  exampleBls12381KeyPair,
  testRevealDocument,
  testSignedDocument,
  customLoader,
  testSignedVcDocument,
  testRevealVcDocument,
  testRevealAllVcDocument,
  testRevealAllDocument,
  testSignedNestedVcDocument,
  testNestedRevealFullDocument,
  testNestedRevealDocument,
  testRevealVcDocumentInvalid,
  testRevealDocumentWithUnknownAttributes
} from "./__fixtures__";
import {
  Bls12381G2KeyPair,
  BbsTermwiseSignatureProof2021,
  BbsTermwiseSignature2021
} from "../src/index";
import { getProofs } from "../src/utilities";

const key = new Bls12381G2KeyPair(exampleBls12381KeyPair);

const rdfdf = new DataFactory();

const document1 = canonize.NQuads.parse(`
<did:example:John> <http://schema.org/birthDate> "1970-01-01"^^<http://schema.org/Date> .
<did:example:John> <http://schema.org/familyName> "Smith" .
<did:example:John> <http://schema.org/givenName> "John" .
<did:example:John> <http://schema.org/homeLocation> <http://example.org/cityA> .
<did:example:John> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
_:6b83e0ac70e <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
_:6b83e0ac70e <https://w3id.org/security#proof> _:6b83e0ac703 .
_:6b83e0ac70e <https://www.w3.org/2018/credentials#credentialSubject> <did:example:John> .
_:6b83e0ac70e <https://www.w3.org/2018/credentials#expirationDate> "2023-11-12T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:6b83e0ac70e <https://www.w3.org/2018/credentials#issuanceDate> "2022-11-12T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:6b83e0ac70e <https://www.w3.org/2018/credentials#issuer> <did:example:issuer1> .
`) as unknown as RDF.Quad[];

const revealedDocument1 = canonize.NQuads.parse(`
<https://zkp-ld.org/.well-known/genid/anonymous/iri#lVhEcU> <http://schema.org/homeLocation> <http://example.org/cityA> .
<https://zkp-ld.org/.well-known/genid/anonymous/iri#lVhEcU> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
_:6b83e0ac70e <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
_:6b83e0ac70e <https://w3id.org/security#proof> _:6b83e0ac703 .
_:6b83e0ac70e <https://www.w3.org/2018/credentials#credentialSubject> <https://zkp-ld.org/.well-known/genid/anonymous/iri#lVhEcU> .
_:6b83e0ac70e <https://www.w3.org/2018/credentials#expirationDate> "2023-11-12T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:6b83e0ac70e <https://www.w3.org/2018/credentials#issuanceDate> "2022-11-12T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:6b83e0ac70e <https://www.w3.org/2018/credentials#issuer> <did:example:issuer1> .
`) as unknown as RDF.Quad[];

const proofs1 = [canonize.NQuads.parse(`
_:6b83e0ac702 <http://purl.org/dc/terms/created> "2022-11-12T06:32:29Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:6b83e0ac703 .
_:6b83e0ac702 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://zkp-ld.org/security#BbsTermwiseSignature2021> _:6b83e0ac703 .
_:6b83e0ac702 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:6b83e0ac703 .
_:6b83e0ac702 <https://w3id.org/security#proofValue> "kjutbi/deDQvhsggZNW//PuyCpjnxAzPopqECZRnxRWbVykWbJcSPlbR9D9ib2GcObDLD+RXIoR9LciOM1vA00krkTa7Sq4ZptWvQUVO0lIEjabe/IY47vUjcc1dEaXPm1xry12rPW/iH1l7iQptHw==" _:6b83e0ac703 .
_:6b83e0ac702 <https://w3id.org/security#verificationMethod> <did:example:issuer1#bbs-bls-key1> _:6b83e0ac703 .
`) as unknown as RDF.Quad[]];

const document2 = canonize.NQuads.parse(`
<http://example.org/cityA> <http://schema.org/maximumAttendeeCapacity> "80000"^^<http://www.w3.org/2001/XMLSchema#integer> .
<http://example.org/cityA> <http://schema.org/name> "City A" .
<http://example.org/cityA> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Place> .
<http://example.org/credentials/3> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<http://example.org/credentials/3> <https://w3id.org/security#proof> _:6b83e0ac70b .
<http://example.org/credentials/3> <https://www.w3.org/2018/credentials#credentialSubject> <http://example.org/cityA> .
<http://example.org/credentials/3> <https://www.w3.org/2018/credentials#expirationDate> "2023-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.org/credentials/3> <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.org/credentials/3> <https://www.w3.org/2018/credentials#issuer> <did:example:issuer3> .
`) as unknown as RDF.Quad[];

const revealedDocument2 = canonize.NQuads.parse(`
<http://example.org/cityA> <http://schema.org/maximumAttendeeCapacity> "https://zkp-ld.org/.well-known/genid/anonymous/literal#ZpJ6Aw"^^<http://www.w3.org/2001/XMLSchema#integer> .
<http://example.org/cityA> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Place> .
<http://example.org/credentials/3> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<http://example.org/credentials/3> <https://w3id.org/security#proof> _:6b83e0ac70b .
<http://example.org/credentials/3> <https://www.w3.org/2018/credentials#credentialSubject> <http://example.org/cityA> .
<http://example.org/credentials/3> <https://www.w3.org/2018/credentials#expirationDate> "2023-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.org/credentials/3> <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.org/credentials/3> <https://www.w3.org/2018/credentials#issuer> <did:example:issuer3> .
`) as unknown as RDF.Quad[];

const proofs2 = [canonize.NQuads.parse(`
_:6b83e0ac70a <http://purl.org/dc/terms/created> "2022-11-12T06:37:01Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:6b83e0ac70b .
_:6b83e0ac70a <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://zkp-ld.org/security#BbsTermwiseSignature2021> _:6b83e0ac70b .
_:6b83e0ac70a <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:6b83e0ac70b .
_:6b83e0ac70a <https://w3id.org/security#proofValue> "q5fZE4huC3w5CY6zkrEO9UvxIqRgFvpW00GwWw1zIDl8zKmwl2OphjabkWK4RYtIL7fhICwFsaFsgmanEPg1At0XFZsuEj79FOGL0T2+2QE+86YlrWVsR0bT/Y/bJZpXCuet6WFkrFL83p23uR5UTQ==" _:6b83e0ac70b .
_:6b83e0ac70a <https://w3id.org/security#verificationMethod> <did:example:issuer3#bbs-bls-key1> _:6b83e0ac70b .
`) as unknown as RDF.Quad[]];

const anonToTerm = new Map<string, RDF.NamedNode | RDF.BlankNode | RDF.Literal>([
  ["https://zkp-ld.org/.well-known/genid/anonymous/iri#lVhEcU",
    rdfdf.namedNode("did:example:John")],
  ["https://zkp-ld.org/.well-known/genid/anonymous/literal#ZpJ6Aw",
    rdfdf.literal("80000", rdfdf.namedNode("'http://www.w3.org/2001/XMLSchema#integer"))],
]);

const inputDocuments = [
  { document: document1, proofs: proofs1, revealedDocument: revealedDocument1, anonToTerm },
  { document: document2, proofs: proofs2, revealedDocument: revealedDocument2, anonToTerm },
];

describe("BbsTermwiseSignatureProof2021", () => {

  it("should derive and verify proof", async () => {
    const suite = new BbsTermwiseSignatureProof2021({
      useNativeCanonize: false,
      key
    });

    const derivedProof: any = await suite.deriveProofMultiRDF({
      inputDocuments,
      documentLoader: customLoader
    });
    expect(derivedProof).toBeDefined();
    console.dir(derivedProof);
  });
});
