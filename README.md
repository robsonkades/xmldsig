# xmldsig

High-performance [XML Digital Signature](https://www.w3.org/TR/xmldsig-core/) library for Brazilian
fiscal documents (NF-e, NFC-e, CT-e, MDF-e, ...).

The signer is immutable and thread-safe: create one instance per certificate at startup and share
it. Everything derivable from the certificate (`KeyInfo`, algorithm objects) is pre-computed once,
and DOM parsing/serialization avoids the per-call `TransformerFactory` pipeline.

## Requirements

- Java 25
- [Apache Santuario (`xmlsec`)](https://santuario.apache.org/) 4.0.4 (transitive dependency)

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

The signature targets the first element (in document order) carrying an `Id` attribute.

Prefer the `byte[]` / stream overloads; the `String` overloads pay two extra full UTF-8
conversions.

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

A valid result means the signature is structurally acceptable and cryptographically consistent. It
does **not** establish trust in the signer's certificate — that comes from the ICP-Brasil chain and
SEFAZ-side validation.

## Algorithms

RSA-SHA1 with SHA-1 digests, as fixed by the SEFAZ signature schema
(`xmldsig-core-schema_v1.01.xsd`) for NF-e/CT-e/MDF-e. SHA-1 is cryptographically weak, but the
algorithm is mandated by the fiscal layout; trust is established by the certificate chain and
SEFAZ-side validation, not by the digest strength.

## Initialization note

Apache Santuario reads `org.apache.xml.security.ignoreLineBreaks` once, at class initialization.
`XmlSigner` sets it and fails fast if another library initialized Santuario first. In that case add
`-Dorg.apache.xml.security.ignoreLineBreaks=true` to the JVM arguments.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
