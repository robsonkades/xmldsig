# xmldsig

[![Maven Central](https://img.shields.io/maven-central/v/io.github.robsonkades/xmldsig.svg)](https://central.sonatype.com/artifact/io.github.robsonkades/xmldsig)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

High-performance [XML Digital Signature](https://www.w3.org/TR/xmldsig-core/) library for Brazilian
fiscal documents (NF-e, NFC-e, CT-e, MDF-e, ...).

The signer is immutable and thread-safe: create one instance per certificate at startup and share
it. Everything derivable from the certificate (`KeyInfo`, algorithm objects) is pre-computed once,
and DOM parsing/serialization avoids the per-call `TransformerFactory` pipeline.

The test suite exercises signing and verification against NF-e, NFC-e, CT-e, MDF-e, NFS-e
(national model) and NF-e event layouts.

## Requirements

- Java 25
- [Apache Santuario (`xmlsec`)](https://santuario.apache.org/) 4.0.4 (pulled in transitively)

The published jar is a full JPMS module named `io.github.robsonkades.xmldsig`. On the classpath it
works as a regular jar.

## Installation

```xml
<dependency>
  <groupId>io.github.robsonkades</groupId>
  <artifactId>xmldsig</artifactId>
  <version>1.0.0</version>
</dependency>
```

## Usage

### Signing

Load the signing material once, then reuse the signer on the hot path:

```java
KeyStore keyStore = KeyStore.getInstance("PKCS12");
try (InputStream in = Files.newInputStream(Path.of("certificate.pfx"))) {
    keyStore.load(in, password);
}

SigningCredential credential = SigningCredential.fromKeyStore(keyStore, password);
XmlSigner signer = XmlSigner.of(credential);   // once, at startup — thread-safe, share it

byte[] signed = signer.sign(xmlBytes);         // hot path
```

Prefer the `byte[]` / stream overloads; the `String` overloads pay two extra full UTF-8
conversions. For servers, the stream overload writes the signed document straight to the
response — the most memory-efficient variant:

```java
signer.sign(inputStream, outputStream);        // streams are flushed, never closed
```

### Document structure

The signature targets the first element (in document order) carrying an `Id` attribute, and the
`Signature` element is appended to the document root, becoming the signed element's sibling. This
matches the SEFAZ layouts (NF-e/NFC-e/CT-e/MDF-e and their events) and the national NFS-e model.

A layout that nests the `Id` element deeper (such as the ABRASF municipal NFS-e) still signs, but
`verifyIntegrity` then rejects it as a possible signature-wrapping attack.

### Customizing the document before signing

`DocumentCustomizer` mutates the parsed DOM in place, sharing a single parse with the signing step —
never customize and sign in separate passes. Customizers compose with `andThen`:

```java
DocumentCustomizer customizer = XmlMinify.minify();   // drop structural whitespace and comments
byte[] signed = signer.sign(xmlBytes, customizer);
```

### Verifying integrity

```java
VerificationResult result = XmlSigner.verifyIntegrity(signedXml);
if (!result.valid()) {
    throw new IllegalStateException(result.detail());
}
```

A valid result means the signature is structurally acceptable (exactly one `Signature`,
whitelisted algorithms and transforms, a unique `Id` resolving to a sibling of the signature —
mitigating signature-wrapping attacks) and cryptographically consistent. It does **not** establish
trust in the signer's certificate — that comes from the ICP-Brasil chain and SEFAZ-side
validation.

### Error handling

All failures surface as unchecked exceptions: `CredentialException` when signing material cannot
be loaded (missing keystore alias, wrong password, no private key), and `XmlSignatureException`
for everything else (malformed XML, document without an `Id` attribute, signing or verification
errors). An invalid signature is **not** an exception — `verifyIntegrity` reports it through
`VerificationResult`.

### Hardware keys (A3)

Software keys (A1) sign concurrently. Hardware tokens (A3 via PKCS#11) serialize signing
operations — a smartcard performs ~10–20 signatures/second regardless of concurrency. Use
`SigningCredential.isLikelyHardwareKey()` to detect them and route signing through a dedicated
bounded executor under high load.

## Algorithms

RSA-SHA1 with SHA-1 digests, as fixed by the SEFAZ signature schema
(`xmldsig-core-schema_v1.01.xsd`) for NF-e/CT-e/MDF-e. SHA-1 is cryptographically weak, but the
algorithm is mandated by the fiscal layout; trust is established by the certificate chain and
SEFAZ-side validation, not by the digest strength.

## Initialization note

Apache Santuario reads `org.apache.xml.security.ignoreLineBreaks` once, at class initialization.
`XmlSigner` sets it and fails fast if another library initialized Santuario first. In that case add
`-Dorg.apache.xml.security.ignoreLineBreaks=true` to the JVM arguments.

## Benchmarks

JMH benchmarks live in [`benchmarks/`](benchmarks) as a standalone project (never published):

```
mvn install                  # install the library snapshot first
cd benchmarks
mvn package
java -jar target/benchmarks.jar
```

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
