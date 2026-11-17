# xmldsig

[![Maven Central](https://img.shields.io/maven-central/v/io.github.robsonkades/xmldsig.svg)](https://central.sonatype.com/artifact/io.github.robsonkades/xmldsig)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

High-performance [XML Digital Signature](https://www.w3.org/TR/xmldsig-core/) library for Brazilian
fiscal documents (NF-e, NFC-e, CT-e, MDF-e, ...).

The signer is immutable and thread-safe: create one instance per certificate at startup and share
it. Everything derivable from the certificate (`KeyInfo`, algorithm objects) is pre-computed once,
and DOM parsing/serialization avoids the per-call `TransformerFactory` pipeline.

The test suite exercises small fixtures shaped like NF-e, NFC-e, CT-e, MDF-e, NFS-e
(national model) and NF-e events. These are structural and cryptographic tests; they do not
establish compliance with an entire fiscal schema or acceptance by an authorizer.

## Requirements

- Java 25 or newer
- [Apache Santuario (`xmlsec`)](https://santuario.apache.org/) 4.0.4 (pulled in transitively)

The published jar is a full JPMS module named `io.github.robsonkades.xmldsig`. On the classpath it
works as a regular jar. Maven also supplies the Jakarta XML Bind/Activation APIs required by
Santuario's module descriptor. A modular consumer declares
`requires io.github.robsonkades.xmldsig;`; DOM types used by `DocumentCustomizer` are readable
through that module.

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

Use `byte[]` or streams for encoded XML. The `String` overload treats the input as Unicode
characters, including when its XML declaration names another encoding. Output uses UTF-8.
The stream overload avoids collecting the output in an additional byte array; parsing and
signing still keep the whole document in memory:

```java
signer.sign(inputStream, outputStream);        // output is flushed; neither stream is closed
```

For untrusted input, configure a limit before building the DOM:

```java
long maxInputBytes = 2L * 1024 * 1024; // example; choose for your fiscal layout
XmlSigner bounded = XmlSigner.of(credential, SignatureAlgorithm.RSA_SHA256, maxInputBytes);
byte[] signed = bounded.sign(xmlBytes);
VerificationResult result = XmlSigner.verifyIntegrity(signed, maxInputBytes + 16 * 1024);
```

The two-argument `XmlSigner.of(credential, maxInputBytes)` retains the RSA-SHA1 default.
Byte arrays and streams count encoded input bytes; strings count their UTF-8 size, including
a leading BOM. A stream may consume one byte beyond the limit to detect overflow. Excess input
throws `XmlSignatureException` before customization, signing or output. Limits must be positive;
factories and verification methods without a limit retain their existing unbounded behavior.
Allow space for the certificate and signature when choosing the verification limit.

The application must also limit request size before allocating a byte array or string, bound
concurrent operations and queued requests, and configure input read deadlines. The parser pool
only bounds cached parsers; it does not limit active operations. A caller timeout alone does not
guarantee interruption of parsing or a hardware signing operation. Customizers are trusted code:
the input limit does not constrain their DOM expansion or the resulting output size.

### Document structure

The supported input is XML 1.0. The signature targets the first element in document order with
an `Id` attribute outside XMLDSig content. That element must be a direct child of the document
root. `Signature` is appended to the same root as a separate sibling. The Id uses the fiscal
ASCII name profile: a letter or underscore followed by letters, digits, underscores, periods
or hyphens. Duplicate target IDs and another sibling with the target's expanded XML name
(namespace plus local name) are rejected as ambiguous.

Signing rejects unsupported structures before producing output, including a root-level Id,
a deeply nested target, and a document already containing a signature. A layout such as an
ABRASF municipal NFS-e may need a different signing structure and is not covered by this contract.
Consumers must use the supported signed element when reading business data: siblings and other
content outside that reference are not authenticated by the signature.

### Customizing the document before signing

`DocumentCustomizer` mutates the parsed DOM in place, sharing a single parse with the signing step —
never customize and sign in separate passes. Customizers compose with `andThen`:

```java
DocumentCustomizer customizer = XmlMinify.minify();   // drop structural whitespace and comments
byte[] signed = signer.sign(xmlBytes, customizer);
```

Namespace declarations are normalized after customization and before calculating the signature.
This can change the canonical representation being signed; it is not a byte-preserving edit of
an already signed document. `XmlMinify` preserves mixed content and `xml:space="preserve"`, and
only removes indentation line breaks from element-only content. Without a schema, treating that
indentation as insignificant remains an assumption about the layout. Comments are omitted
when the signed XML is serialized.

### Verifying integrity

```java
VerificationResult result = XmlSigner.verifyIntegrity(signedXml);
if (!result.valid()) {
    throw new IllegalStateException(result.detail());
}
```

A valid result means the signature follows the document structure above (exactly one `Signature`,
allowed algorithms and transforms, one unique reference to the supported target) and is
cryptographically consistent. It does **not** establish
trust in the signer's certificate — that comes from the ICP-Brasil chain and SEFAZ-side
validation.

Signing and verification support inclusive C14N 1.0 **without comments**. XML comments are
discarded and are not authenticated. Algorithms with comments are rejected explicitly, even
when another XMLDSig implementation considers the signature valid.

Before provider unmarshalling, verification checks the signature structure, algorithms,
reference/transform counts and embedded-key forms. `KeyInfo` must contain `X509Data` with an
embedded certificate; certificate chains and `X509IssuerSerial`, `X509SubjectName` and `X509SKI`
metadata are accepted. `RetrievalMethod`, raw `KeyValue`, CRLs and other key forms are rejected.

Only the sole `SignedInfo` reference is authenticated. Auxiliary `Object`/`Manifest` content is
not cryptographically validated or dereferenced; its algorithms are checked before unmarshalling.
Consumers must not treat it as authenticated business data.

### Error handling

Failures surface as unchecked exceptions: `CredentialException` when signing material cannot
be loaded (missing keystore alias, wrong password, no private key), and `XmlSignatureException`
for everything else (malformed XML, document without an `Id` attribute, signing or verification
errors). Policy rejections and completed validations with a negative result are reported through
`VerificationResult`; malformed input and failures that prevent validation can throw
`XmlSignatureException`. Null configuration arguments may throw `NullPointerException`;
nonpositive input limits throw `IllegalArgumentException`.

### Hardware keys (A3)

Software keys (A1) can sign concurrently. Hardware-token throughput and concurrency depend on
the PKCS#11 provider and device; measure them in the target environment. Use
`SigningCredential.isLikelyHardwareKey()` to detect them and route signing through a dedicated
bounded executor under high load.

## Algorithms

The default is RSA-SHA1 with SHA-1 digests, retained for fiscal layouts that require it.
RSA-SHA256 with SHA-256 digests is also available:

```java
XmlSigner signer = XmlSigner.of(credential, SignatureAlgorithm.RSA_SHA256);
```

Select the algorithm required by the exact layout/version and authorizer. The verifier accepts
both supported signature and digest algorithms. Certificate trust and signature integrity are
separate requirements;
certificate-chain validation does not remove SHA-1's cryptographic limitations.

## Initialization note

Apache Santuario reads `org.apache.xml.security.ignoreLineBreaks` once, at class initialization.
`XmlSigner` sets it and fails fast if another library initialized Santuario first. In that case add
`-Dorg.apache.xml.security.ignoreLineBreaks=true` to the JVM arguments.

## Benchmarks

JMH benchmarks live in [`benchmarks/`](benchmarks) as a standalone project (never published):

```bash
sh ./mvnw clean install
library_version=$(sh ./mvnw -q org.apache.maven.plugins:maven-help-plugin:3.5.2:evaluate -Dexpression=project.version -DforceStdout)
sh ./mvnw -f benchmarks/pom.xml clean package -Dxmldsig.version="$library_version"
java -jar benchmarks/target/benchmarks.jar
```

In PowerShell, use `.\mvnw.cmd` in place of `sh ./mvnw`, and `$libraryVersion = .\mvnw.cmd -q org.apache.maven.plugins:maven-help-plugin:3.5.2:evaluate '-Dexpression=project.version' '-DforceStdout'`
and pass `"-Dxmldsig.version=$libraryVersion"` to the benchmark build. Pass the installed library
version explicitly so a release checkout cannot silently benchmark an older snapshot. Record
the commit, JDK, hardware, algorithm, input size, threads and raw JMH output with performance claims.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
