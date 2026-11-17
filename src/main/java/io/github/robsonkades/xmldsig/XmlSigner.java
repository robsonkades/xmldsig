/*
 * Copyright 2026 Robson Kades
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.github.robsonkades.xmldsig;

import org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.apache.xml.security.Init;
import org.apache.xml.security.utils.XMLUtils;
import org.jspecify.annotations.Nullable;
import org.w3c.dom.Document;
import org.w3c.dom.Attr;
import org.w3c.dom.DOMError;
import org.w3c.dom.DOMErrorHandler;
import org.w3c.dom.DOMException;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import org.xml.sax.InputSource;

import javax.xml.XMLConstants;
import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.FilterInputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.ArrayList;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.regex.Pattern;

/**
 * High-performance XMLDSig signer for Brazilian fiscal documents (NF-e, NFC-e, CT-e, MDF-e, ...).
 *
 * <p><b>Usage:</b> create one instance per certificate at startup and share it — the instance is
 * immutable and thread-safe, and pre-computes everything derivable from the certificate
 * ({@code KeyInfo}, algorithm objects):
 *
 * <pre>{@code
 * SigningCredential credential = SigningCredential.fromKeyStore(keyStore, keyPassword);
 * XmlSigner signer = XmlSigner.of(credential);              // once
 * byte[] signed = signer.sign(xmlBytes);                    // hot path
 * byte[] customized = signer.sign(xmlBytes, document -> {  // sign with in-place customization
 *     // mutate the DOM before signing
 * });
 * }</pre>
 *
 * <p><b>Document structure:</b> the signature is appended to the document's root element, and the
 * signed element — the first element in document order carrying an {@code Id} attribute — is
 * required to be a direct child of that root, so the signature becomes its sibling. This matches
 * the SEFAZ layouts (NF-e/NFC-e/CT-e/MDF-e and their events) and the national NFS-e model. A layout
 * that nests the {@code Id} element deeper (such as the ABRASF municipal NFS-e) is rejected.
 * IDs use the fiscal ASCII NCName profile: a letter or underscore followed by letters, digits,
 * underscores, dots or hyphens. Ambiguous siblings with the target's QName are rejected.
 * A document that already contains a {@code Signature} element is rejected before signing:
 * re-signing produces a twice-signed document no authorizer accepts. Re-emission flows should
 * remove the old signature in a {@link DocumentCustomizer}, which runs before this check.
 *
 * <p><b>Performance notes:</b>
 * <ul>
 *   <li>Prefer the {@code byte[]}/stream overloads when input is already encoded. The {@code String}
 *       overload parses character input directly and converts the UTF-8 output to a String.</li>
 *   <li>{@link DocumentBuilder} instances are pooled in a small bounded queue — safe and
 *       effective under both platform and virtual threads (a {@code ThreadLocal} cache would be
 *       useless under virtual threads).</li>
 *   <li>The element-with-Id lookup is a direct DOM walk (no XPath/DTM), supporting any fiscal
 *       document type ({@code NFe...}, {@code CTe...}, {@code MDFe...}, {@code ID...} ids).</li>
 *   <li>Serialization uses {@link DomSerializer}; XML comments are always dropped (they are
 *       excluded from inclusive C14N, so signatures are unaffected).</li>
 * </ul>
 *
 * <p><b>Algorithms:</b> RSA-SHA1 with SHA-1 digests by default, as fixed by the SEFAZ signature
 * schema ({@code xmldsig-core-schema_v1.01.xsd}) for NF-e/CT-e/MDF-e. SHA-1 is cryptographically
 * weak, but the algorithm is mandated by the fiscal layout; trust is established by the
 * ICP-Brasil chain and SEFAZ-side validation, not by the digest strength. For layouts that
 * mandate SHA-256 instead, create the signer with
 * {@link #of(SigningCredential, SignatureAlgorithm)}.
 *
 * <p><b>Initialization requirement:</b> Apache Santuario reads
 * {@code org.apache.xml.security.ignoreLineBreaks} once, at class initialization. This class sets
 * it and fails fast if another library initialized Santuario first; in that case add
 * {@code -Dorg.apache.xml.security.ignoreLineBreaks=true} to the JVM arguments.
 *
 * @since 1.0
 */
public final class XmlSigner {

    private static final String ID_ATTRIBUTE = "Id";
    private static final Pattern FISCAL_ID = Pattern.compile("[A-Za-z_][A-Za-z0-9_.-]*");
    private static final int SIGNATURE_OVERHEAD_ESTIMATE = 4096;
    private static final int MIN_RSA_KEY_BITS = 1024;
    private static final String EXTERNAL_GENERAL_ENTITIES = "http://xml.org/sax/features/external-general-entities";
    private static final String EXTERNAL_PARAMETER_ENTITIES = "http://xml.org/sax/features/external-parameter-entities";
    private static final String DISALLOW_DOCTYPE_DECL = "http://apache.org/xml/features/disallow-doctype-decl";
    private static final String DEFER_NODE_EXPANSION = "http://apache.org/xml/features/dom/defer-node-expansion";
    private static final String ORG_JCP_XML_DSIG_SECURE_VALIDATION = "org.jcp.xml.dsig.secureValidation";

    private static final String ORG_APACHE_XML_SECURITY_IGNORE_LINE_BREAKS = "org.apache.xml.security.ignoreLineBreaks";

    static {
        // Must run before any Santuario class initializes: the flag is read exactly once.
        if (System.getProperty(ORG_APACHE_XML_SECURITY_IGNORE_LINE_BREAKS) == null) {
            System.setProperty(ORG_APACHE_XML_SECURITY_IGNORE_LINE_BREAKS, "true");
        }
        if (!Init.isInitialized()) {
            Init.init();
        }
        if (!XMLUtils.ignoreLineBreaks()) {
            throw new IllegalStateException("""
                    Apache Santuario was initialized before ignoreLineBreaks was set; signatures \
                    would contain line breaks and be rejected by SEFAZ. \
                    Add -Dorg.apache.xml.security.ignoreLineBreaks=true to the JVM arguments.""");
        }
    }

    private static final XMLSignatureFactory SIGNATURE_FACTORY = XMLSignatureFactory.getInstance("DOM", new XMLDSigRI());

    // DigestMethod is immutable in the DOM provider — safe to share. SignatureMethod is NOT:
    // Santuario's DOMSignatureMethod caches a java.security.Signature instance (not thread-safe)
    // on the object, so it must be created per signing operation, like Transform and
    // CanonicalizationMethod (which carry marshalling state).
    private static final DigestMethod SHA1_DIGEST_METHOD = newDigestMethod(DigestMethod.SHA1);
    private static final DigestMethod SHA256_DIGEST_METHOD = newDigestMethod(DigestMethod.SHA256);

    private static final DocumentBuilderFactory DOCUMENT_BUILDER_FACTORY = createDocumentBuilderFactory();
    private static final int PARSER_POOL_MAX = Math.max(8, Runtime.getRuntime().availableProcessors() * 2);
    // ArrayBlockingQueue used purely non-blockingly (poll/offer): intrinsically bounded, and its
    // size check is O(1) — ConcurrentLinkedQueue.size() traverses the whole queue.
    private static final ArrayBlockingQueue<DocumentBuilder> PARSER_POOL = new ArrayBlockingQueue<>(PARSER_POOL_MAX);

    private static final KeySelector EMBEDDED_CERTIFICATE_KEY_SELECTOR = new EmbeddedCertificateKeySelector();
    // Parsing/serialization intentionally discard comments. Never claim to authenticate them.
    private static final Set<String> ALLOWED_CANONICALIZATION = Set.of(CanonicalizationMethod.INCLUSIVE);
    private static final Set<String> ALLOWED_SIGNATURE_METHODS = Set.of(SignatureMethod.RSA_SHA1, SignatureMethod.RSA_SHA256);
    private static final Set<String> ALLOWED_DIGEST_METHODS = Set.of(DigestMethod.SHA1, DigestMethod.SHA256);
    private static final Set<String> ALLOWED_TRANSFORMS = Set.of(Transform.ENVELOPED, CanonicalizationMethod.INCLUSIVE);
    private static final Set<String> ALLOWED_X509_DATA = Set.of("X509Certificate", "X509IssuerSerial", "X509SubjectName", "X509SKI");
    private static final int MAX_TRANSFORMS = 3;

    private final PrivateKey privateKey;
    private final KeyInfo keyInfo;
    private final String signatureMethodUri;
    private final DigestMethod digestMethod;
    private final long maxInputBytes;

    private XmlSigner(final SigningCredential credential, final SignatureAlgorithm algorithm, long maxInputBytes) {
        this.maxInputBytes = requirePositiveLimit(maxInputBytes);
        this.privateKey = credential.privateKey();
        this.signatureMethodUri = switch (algorithm) {
            case RSA_SHA1 -> SignatureMethod.RSA_SHA1;
            case RSA_SHA256 -> SignatureMethod.RSA_SHA256;
        };
        this.digestMethod = switch (algorithm) {
            case RSA_SHA1 -> SHA1_DIGEST_METHOD;
            case RSA_SHA256 -> SHA256_DIGEST_METHOD;
        };
        KeyInfoFactory keyInfoFactory = SIGNATURE_FACTORY.getKeyInfoFactory();
        X509Data x509Data = keyInfoFactory.newX509Data(List.of(credential.leafCertificate()));
        this.keyInfo = keyInfoFactory.newKeyInfo(List.of(x509Data));
    }

    /**
     * Creates a signer for the given credential using the SEFAZ default,
     * {@link SignatureAlgorithm#RSA_SHA1}. Create once per certificate and share.
     *
     * @param credential the signing material; must not be {@code null}
     * @return an immutable, thread-safe signer bound to the credential
     */
    public static XmlSigner of(SigningCredential credential) {
        return of(credential, SignatureAlgorithm.RSA_SHA1);
    }

    /**
     * Creates a signer for the given credential and signature algorithm. Only select
     * {@link SignatureAlgorithm#RSA_SHA256} when the fiscal layout mandates it.
     *
     * @param credential the signing material; must not be {@code null}
     * @param algorithm  the signature/digest algorithm pair; must not be {@code null}
     * @return an immutable, thread-safe signer bound to the credential
     */
    public static XmlSigner of(SigningCredential credential, SignatureAlgorithm algorithm) {
        return of(credential, algorithm, Long.MAX_VALUE);
    }

    /**
     * Creates a signer using RSA-SHA1 with an input size limit.
     *
     * @param credential the signing material
     * @param maxInputBytes maximum encoded input bytes; positive
     * @return an immutable, thread-safe signer
     * @see #of(SigningCredential, SignatureAlgorithm, long)
     */
    public static XmlSigner of(SigningCredential credential, long maxInputBytes) {
        return of(credential, SignatureAlgorithm.RSA_SHA1, maxInputBytes);
    }

    /**
     * Creates a signer with an input size limit. Byte arrays and streams count encoded bytes;
     * strings count their UTF-8 size, including any leading BOM. A stream may consume one extra
     * byte to detect overflow. Oversized input throws {@link XmlSignatureException} before
     * customization, signing or writing output. The limit does not bound customizer expansion
     * or output size. Existing factories without a limit remain unbounded.
     *
     * @param credential the signing material; must not be {@code null}
     * @param algorithm the signature/digest algorithm pair; must not be {@code null}
     * @param maxInputBytes maximum encoded input bytes; positive
     * @return an immutable, thread-safe signer
     * @throws IllegalArgumentException if the limit is not positive
     */
    public static XmlSigner of(SigningCredential credential, SignatureAlgorithm algorithm, long maxInputBytes) {
        return new XmlSigner(
                Objects.requireNonNull(credential, "credential must not be null"),
                Objects.requireNonNull(algorithm, "algorithm must not be null"), maxInputBytes);
    }

    /**
     * Signs the XML and returns the signed document. The signature targets the first element
     * (in document order) carrying an {@code Id} attribute.
     *
     * @param xml the UTF-8 encoded XML document; must not be {@code null} or empty
     * @return the signed document as UTF-8 bytes
     */
    public byte[] sign(byte[] xml) {
        return doSign(xml, null);
    }

    /**
     * Applies the customizer to the parsed document, then signs. Customization and signing share a
     * single parse — never customize and sign in separate passes.
     *
     * @param xml        the UTF-8 encoded XML document; must not be {@code null} or empty
     * @param customizer mutates the parsed DOM before signing; must not be {@code null}
     * @return the signed document as UTF-8 bytes
     */
    public byte[] sign(byte[] xml, DocumentCustomizer customizer) {
        Objects.requireNonNull(customizer, "customizer must not be null");
        return doSign(xml, customizer);
    }

    /**
     * Convenience {@code String} variant. Parses Unicode characters directly, independently of
     * the encoding declaration. Prefer {@link #sign(byte[])} when the input is already bytes.
     *
     * @param xml the XML document; must not be {@code null} or blank
     * @return the signed document
     */
    public String sign(String xml) {
        return signToString(xml, null);
    }

    /**
     * Convenience {@code String} variant of {@link #sign(byte[], DocumentCustomizer)}.
     *
     * @param xml        the XML document; must not be {@code null} or blank
     * @param customizer mutates the parsed DOM before signing; must not be {@code null}
     * @return the signed document
     */
    public String sign(String xml, DocumentCustomizer customizer) {
        Objects.requireNonNull(customizer, "customizer must not be null");
        return signToString(xml, customizer);
    }

    /**
     * Signs the XML read from {@code input} and writes the signed document to {@code output}.
     * The most memory-efficient variant for server use — pass the response stream directly.
     *
     * @param input  stream supplying the XML document; not closed by this method
     * @param output stream receiving the signed document; flushed but not closed
     */
    public void sign(InputStream input, OutputStream output) {
        doSign(input, output, null);
    }

    /**
     * Stream variant of {@link #sign(byte[], DocumentCustomizer)}.
     *
     * @param input      stream supplying the XML document; not closed by this method
     * @param output     stream receiving the signed document; flushed but not closed
     * @param customizer mutates the parsed DOM before signing; must not be {@code null}
     */
    public void sign(InputStream input, OutputStream output, DocumentCustomizer customizer) {
        Objects.requireNonNull(customizer, "customizer must not be null");
        doSign(input, output, customizer);
    }

    private String signToString(String xml, @Nullable DocumentCustomizer customizer) {
        if (xml == null || xml.isBlank()) {
            throw new XmlSignatureException("XML must not be null or empty");
        }
        checkInputSize(xml, maxInputBytes);
        try {
            Document document = parseCustomizeSign(characterInput(xml), customizer);
            return new String(DomSerializer.writeToBytes(document, SIGNATURE_OVERHEAD_ESTIMATE), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new XmlSignatureException("XML signing failed", e);
        }
    }

    private byte[] doSign(byte[] xml, @Nullable DocumentCustomizer customizer) {
        if (xml == null || xml.length == 0) {
            throw new XmlSignatureException("XML must not be null or empty");
        }
        checkInputSize(xml.length, maxInputBytes);
        try {
            Document document = parseCustomizeSign(new ByteArrayInputStream(xml), customizer);
            return DomSerializer.writeToBytes(document, xml.length + SIGNATURE_OVERHEAD_ESTIMATE);
        } catch (IOException e) {
            throw new XmlSignatureException("XML signing failed", e);
        }
    }

    private void doSign(InputStream input, OutputStream output, @Nullable DocumentCustomizer customizer) {
        Objects.requireNonNull(input, "input must not be null");
        Objects.requireNonNull(output, "output must not be null");
        try {
            Document document = parseCustomizeSign(maxInputBytes == Long.MAX_VALUE
                    ? input : new LimitedInputStream(input, maxInputBytes), customizer);
            DomSerializer.write(document, output);
        } catch (IOException e) {
            throw new XmlSignatureException("XML signing failed", e);
        }
    }

    private Document parseCustomizeSign(InputStream input, @Nullable DocumentCustomizer customizer) {
        return parseCustomizeSign(new InputSource(nonClosing(input)), customizer);
    }

    private Document parseCustomizeSign(InputSource input, @Nullable DocumentCustomizer customizer) {
        try {
            Document document = parse(input);
            if (customizer != null) {
                customizer.customize(document);
                prepareCustomizedDocument(document);
            }
            signInPlace(document);
            return document;
        } catch (SAXException e) {
            throw new XmlSignatureException("Malformed XML content", e);
        } catch (GeneralSecurityException | MarshalException | XMLSignatureException | IOException | DOMException e) {
            throw new XmlSignatureException("XML signing failed", e);
        }
    }

    private static void prepareCustomizedDocument(Document document) {
        if (!"1.0".equals(document.getXmlVersion()) || document.getDoctype() != null
                || document.getDocumentElement() == null) {
            throw new XmlSignatureException("Customizer must produce an XML 1.0 document without a DTD");
        }
        // DOM Level 3 repairs namespace declarations before digesting the customized content.
        // Capture errors explicitly: normalizeDocument may report them without throwing.
        makeNamespaceAware(document.getDocumentElement(), document);
        String[] error = new String[1];
        document.getDomConfig().setParameter("error-handler", (DOMErrorHandler) issue -> {
            if (issue.getSeverity() >= DOMError.SEVERITY_ERROR) {
                error[0] = issue.getMessage();
                return false;
            }
            return true;
        });
        document.getDomConfig().setParameter("namespaces", true);
        document.getDomConfig().setParameter("namespace-declarations", true);
        document.getDomConfig().setParameter("well-formed", true);
        document.getDomConfig().setParameter("split-cdata-sections", true);
        document.getDomConfig().setParameter("validate", false);
        document.normalizeDocument();
        if (error[0] != null) {
            throw new XmlSignatureException("Invalid customized XML: " + error[0]);
        }
        rejectUnserializableInstructions(document.getDocumentElement());
    }

    private static void makeNamespaceAware(Element element, Document document) {
        if (element.getLocalName() == null) {
            Element replacement = document.createElementNS(null, element.getNodeName());
            while (element.hasAttributes()) {
                Attr attribute = (Attr) element.getAttributes().item(0);
                element.removeAttributeNode(attribute);
                replacement.setAttributeNodeNS(attribute);
            }
            while (element.hasChildNodes()) {
                replacement.appendChild(element.getFirstChild());
            }
            element.getParentNode().replaceChild(replacement, element);
            element = replacement;
        }
        List<Attr> attributes = new ArrayList<>(element.getAttributes().getLength());
        for (int i = 0; i < element.getAttributes().getLength(); i++) {
            attributes.add((Attr) element.getAttributes().item(i));
        }
        for (Attr attribute : attributes) {
            if (attribute.getLocalName() == null) {
                String name = attribute.getName();
                String namespace = name.equals("xmlns") || name.startsWith("xmlns:")
                        ? XMLConstants.XMLNS_ATTRIBUTE_NS_URI
                        : name.startsWith("xml:") ? XMLConstants.XML_NS_URI : null;
                Attr replacement = document.createAttributeNS(namespace, name);
                replacement.setValue(attribute.getValue());
                element.removeAttributeNode(attribute);
                element.setAttributeNodeNS(replacement);
            }
        }
        for (Node child = element.getFirstChild(); child != null;) {
            Node next = child.getNextSibling();
            if (child instanceof Element childElement) {
                makeNamespaceAware(childElement, document);
            }
            child = next;
        }
    }

    private static void rejectUnserializableInstructions(Node node) {
        if (node.getNodeType() == Node.PROCESSING_INSTRUCTION_NODE && node.getNodeValue().indexOf('\r') >= 0) {
            throw new XmlSignatureException("A processing instruction cannot contain a carriage return");
        }
        for (Node child = node.getFirstChild(); child != null; child = child.getNextSibling()) {
            rejectUnserializableInstructions(child);
        }
    }

    private void signInPlace(Document document) throws GeneralSecurityException, MarshalException, XMLSignatureException {
        // Fail fast instead of producing a twice-signed document, which every authorizer rejects.
        // Runs after the customizer, so re-emission flows may drop an old Signature and re-sign.
        if (containsSignature(document.getDocumentElement())) {
            throw new XmlSignatureException(
                    "Document already contains a Signature element; re-signing a signed document is not supported");
        }
        Element target = findElementWithId(document);
        String id = target.getAttribute(ID_ATTRIBUTE);
        if (!FISCAL_ID.matcher(id).matches()) {
            throw new XmlSignatureException("Signable element must have a simple fiscal Id (ASCII NCName)");
        }
        List<Element> targets = new ArrayList<>(1);
        collectElementsById(document.getDocumentElement(), id, targets);
        if (targets.size() != 1) {
            throw new XmlSignatureException("Multiple elements with Id='" + id + "' found");
        }
        String targetRejection = checkBusinessTarget(target, document);
        if (targetRejection != null) {
            throw new XmlSignatureException(targetRejection);
        }
        target.setIdAttribute(ID_ATTRIBUTE, true);

        Reference reference = SIGNATURE_FACTORY.newReference(
                "#" + id,
                digestMethod,
                List.of(SIGNATURE_FACTORY.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null),
                        SIGNATURE_FACTORY.newTransform(CanonicalizationMethod.INCLUSIVE,
                                (TransformParameterSpec) null)),
                null,
                null);

        SignedInfo signedInfo = SIGNATURE_FACTORY.newSignedInfo(
                SIGNATURE_FACTORY.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE,
                        (C14NMethodParameterSpec) null),
                SIGNATURE_FACTORY.newSignatureMethod(signatureMethodUri, null),
                List.of(reference));

        XMLSignature signature = SIGNATURE_FACTORY.newXMLSignature(signedInfo, keyInfo);
        signature.sign(new DOMSignContext(privateKey, document.getDocumentElement()));
    }

    // ------------------------------------------------------------------
    // Verification
    // ------------------------------------------------------------------

    /**
     * Verifies the <b>integrity</b> of the embedded signature: structural sanity (exactly one
     * signature, whitelisted algorithms and transforms, same-document reference resolving to a
     * unique sibling element — mitigating signature-wrapping attacks) plus cryptographic consistency
     * against the certificate embedded in {@code KeyInfo}.
     * Only inclusive C14N without comments is supported; comments are not authenticated.
     * {@code KeyInfo} must contain embedded {@code X509Data}, optionally with certificate
     * identity metadata. Remote key references, raw key values and CRLs are not supported.
     *
     * <p><b>This does not establish trust.</b> Any attacker can re-sign a tampered document with
     * their own certificate and pass this check. Authenticity requires validating the certificate
     * chain against ICP-Brasil trust anchors, which SEFAZ performs on submission.
     *
     * @param xml the signed UTF-8 encoded XML document; must not be {@code null} or empty
     * @return the verification outcome, with a human-readable reason when invalid
     */
    public static VerificationResult verifyIntegrity(byte[] xml) {
        return verifyIntegrity(xml, Long.MAX_VALUE);
    }

    /**
     * Verifies integrity with an encoded input size limit, checked before parsing.
     *
     * @param xml the signed XML bytes
     * @param maxInputBytes maximum input bytes; positive
     * @return the integrity verification outcome; does not establish certificate trust
     * @throws IllegalArgumentException if the limit is not positive
     * @throws XmlSignatureException if the input exceeds the limit
     */
    public static VerificationResult verifyIntegrity(byte[] xml, long maxInputBytes) {
        requirePositiveLimit(maxInputBytes);
        if (xml == null || xml.length == 0) {
            throw new XmlSignatureException("XML must not be null or empty");
        }
        checkInputSize(xml.length, maxInputBytes);
        Document document;
        try {
            document = parse(new ByteArrayInputStream(xml));
        } catch (SAXException e) {
            throw new XmlSignatureException("Malformed XML content", e);
        } catch (IOException e) {
            throw new XmlSignatureException("I/O error reading XML", e);
        }
        return verifyIntegrity(document);
    }

    /**
     * Convenience {@code String} variant of {@link #verifyIntegrity(byte[])}.
     *
     * @param xml the signed XML document; must not be {@code null} or blank
     * @return the verification outcome, with a human-readable reason when invalid
     */
    public static VerificationResult verifyIntegrity(String xml) {
        return verifyIntegrity(xml, Long.MAX_VALUE);
    }

    /**
     * String variant of {@link #verifyIntegrity(byte[], long)}, counting UTF-8 bytes including
     * any leading BOM, independently of the XML encoding declaration.
     *
     * @param xml the signed XML string
     * @param maxInputBytes maximum UTF-8 input bytes; positive
     * @return the integrity verification outcome; does not establish certificate trust
     * @throws IllegalArgumentException if the limit is not positive
     * @throws XmlSignatureException if the input exceeds the limit
     */
    public static VerificationResult verifyIntegrity(String xml, long maxInputBytes) {
        requirePositiveLimit(maxInputBytes);
        if (xml == null || xml.isBlank()) {
            throw new XmlSignatureException("XML must not be null or empty");
        }
        checkInputSize(xml, maxInputBytes);
        try {
            return verifyIntegrity(parse(characterInput(xml)));
        } catch (SAXException e) {
            throw new XmlSignatureException("Malformed XML content", e);
        } catch (IOException e) {
            throw new XmlSignatureException("I/O error reading XML", e);
        }
    }

    private static VerificationResult verifyIntegrity(Document document) {
        NodeList signatures = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (signatures.getLength() == 0) {
            return VerificationResult.invalid("No Signature element found");
        }
        if (signatures.getLength() > 1) {
            return VerificationResult.invalid("Multiple Signature elements found (possible signature wrapping)");
        }
        Element signatureElement = (Element) signatures.item(0);
        if (signatureElement.getParentNode() != document.getDocumentElement()) {
            return VerificationResult.invalid("Signature must be a direct child of the document root");
        }
        String preflightRejection = checkSignaturePreflight(signatureElement);
        if (preflightRejection != null) {
            return VerificationResult.invalid(preflightRejection);
        }

        DOMValidateContext context = new DOMValidateContext(EMBEDDED_CERTIFICATE_KEY_SELECTOR, signatureElement);
        // SEFAZ mandates RSA-SHA1, which the generic JDK/Santuario secure-validation blacklist
        // rejects on modern JDKs. The blacklist is disabled and replaced by the stricter
        // whitelist enforced in checkSignaturePolicy (fixed algorithms, single same-document
        // reference, bounded transforms, minimum RSA key size).
        context.setProperty(ORG_JCP_XML_DSIG_SECURE_VALIDATION, Boolean.FALSE);

        try {
            XMLSignature signature = SIGNATURE_FACTORY.unmarshalXMLSignature(context);
            String rejection = checkSignaturePolicy(signature, signatureElement, document, context);
            if (rejection != null) {
                return VerificationResult.invalid(rejection);
            }
            return signature.validate(context)
                    ? VerificationResult.ok()
                    : VerificationResult.invalid("Digest or signature value mismatch");
        } catch (MarshalException | XMLSignatureException e) {
            throw new XmlSignatureException("Unable to validate XML signature", e);
        }
    }

    /**
     * Rejects unsupported structures before the provider instantiates algorithm services or
     * decodes key material. The post-unmarshal policy still checks the provider's interpretation
     * and binds the unique business target. This is a profile check, not an XMLDSig schema validator.
     */
    private static @Nullable String checkSignaturePreflight(Element signature) {
        List<Element> children = childElements(signature);
        if (children.size() < 3 || !isSignatureElement(children.get(0), "SignedInfo")
                || !isSignatureElement(children.get(1), "SignatureValue")
                || !isSignatureElement(children.get(2), "KeyInfo")) {
            return "Expected SignedInfo, SignatureValue and KeyInfo in Signature";
        }
        for (int i = 3; i < children.size(); i++) {
            if (!isSignatureElement(children.get(i), "Object")) {
                return "Only Object elements may follow KeyInfo";
            }
        }
        List<Element> signedInfo = childElements(children.getFirst());
        long references = signedInfo.stream().filter(element -> isSignatureElement(element, "Reference")).count();
        if (references != 1) {
            return "Expected exactly one Reference, found " + references;
        }
        if (signedInfo.size() != 3 || !isSignatureElement(signedInfo.get(0), "CanonicalizationMethod")
                || !isSignatureElement(signedInfo.get(1), "SignatureMethod")
                || !isSignatureElement(signedInfo.get(2), "Reference")) {
            return "Expected CanonicalizationMethod, SignatureMethod and Reference in SignedInfo";
        }
        String uriRejection = checkReferenceUri(signedInfo.get(2).getAttribute("URI"));
        if (uriRejection != null) {
            return uriRejection;
        }
        boolean certificateFound = false;
        for (Element data : childElements(children.get(2))) {
            if (!isSignatureElement(data, "X509Data")) {
                return "Disallowed KeyInfo content: " + data.getLocalName();
            }
            for (Element item : childElements(data)) {
                if (!XMLSignature.XMLNS.equals(item.getNamespaceURI())
                        || !ALLOWED_X509_DATA.contains(item.getLocalName())) {
                    return "Disallowed X509Data content: " + item.getLocalName();
                }
                certificateFound |= isSignatureElement(item, "X509Certificate");
            }
        }
        if (!certificateFound) {
            return "No X509Certificate found in KeyInfo";
        }
        return checkAlgorithmElements(signature);
    }

    private static @Nullable String checkAlgorithmElements(Element element) {
        List<Element> children = childElements(element);
        if (XMLSignature.XMLNS.equals(element.getNamespaceURI())) {
            String name = element.getLocalName();
            if ("Reference".equals(name)) {
                int digestIndex = !children.isEmpty() && isSignatureElement(children.getFirst(), "Transforms") ? 1 : 0;
                if (children.size() != digestIndex + 2
                        || !isSignatureElement(children.get(digestIndex), "DigestMethod")
                        || !isSignatureElement(children.get(digestIndex + 1), "DigestValue")) {
                    return "Expected optional Transforms, DigestMethod and DigestValue in Reference";
                }
            }
            if ("Transforms".equals(name)) {
                if (children.size() > MAX_TRANSFORMS) {
                    return "Too many transforms: " + children.size();
                }
                for (Element child : children) {
                    if (!isSignatureElement(child, "Transform")) {
                        return "Expected Transform elements in the XMLDSig namespace";
                    }
                }
            }
            Set<String> allowed = switch (name) {
                case "CanonicalizationMethod" -> ALLOWED_CANONICALIZATION;
                case "SignatureMethod" -> ALLOWED_SIGNATURE_METHODS;
                case "DigestMethod" -> ALLOWED_DIGEST_METHODS;
                case "Transform" -> ALLOWED_TRANSFORMS;
                default -> null;
            };
            if (allowed != null) {
                String algorithm = element.getAttribute("Algorithm");
                if (!allowed.contains(algorithm)) {
                    String label = switch (name) {
                        case "CanonicalizationMethod" -> "canonicalization method";
                        case "SignatureMethod" -> "signature method";
                        case "DigestMethod" -> "digest method";
                        default -> "transform";
                    };
                    return "Disallowed " + label + ": " + algorithm;
                }
                if (!children.isEmpty()) {
                    return "Parameters are not supported for " + name;
                }
            }
        }
        // Object/Manifest content can also instantiate transforms during unmarshalling,
        // even though auxiliary references are never treated as authenticated business data.
        for (Element child : children) {
            String rejection = checkAlgorithmElements(child);
            if (rejection != null) {
                return rejection;
            }
        }
        return null;
    }

    private static boolean isSignatureElement(Element element, String name) {
        return XMLSignature.XMLNS.equals(element.getNamespaceURI()) && name.equals(element.getLocalName());
    }

    private static List<Element> childElements(Element parent) {
        List<Element> elements = new ArrayList<>();
        for (Node child = parent.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child instanceof Element element) {
                elements.add(element);
            }
        }
        return elements;
    }

    private static @Nullable String checkReferenceUri(@Nullable String uri) {
        if (uri == null || uri.length() < 2 || uri.charAt(0) != '#') {
            return "Reference URI must be a same-document Id reference";
        }
        return FISCAL_ID.matcher(uri.substring(1)).matches()
                ? null : "Reference URI must contain a simple fiscal Id (ASCII NCName)";
    }

    /**
     * Returns a rejection reason, or {@code null} if the signature passes the structural policy.
     * As a side effect, registers the signed element's Id for reference dereferencing.
     */
    private static @Nullable String checkSignaturePolicy(XMLSignature signature, Element signatureElement,
                                                        Document document, DOMValidateContext context) {
        SignedInfo signedInfo = signature.getSignedInfo();

        String canonicalization = signedInfo.getCanonicalizationMethod().getAlgorithm();
        if (!ALLOWED_CANONICALIZATION.contains(canonicalization)) {
            return "Disallowed canonicalization method: " + canonicalization;
        }
        String signatureMethod = signedInfo.getSignatureMethod().getAlgorithm();
        if (!ALLOWED_SIGNATURE_METHODS.contains(signatureMethod)) {
            return "Disallowed signature method: " + signatureMethod;
        }

        List<Reference> references = signedInfo.getReferences();
        if (references.size() != 1) {
            return "Expected exactly one Reference, found " + references.size();
        }
        Reference reference = references.getFirst();

        String digestMethod = reference.getDigestMethod().getAlgorithm();
        if (!ALLOWED_DIGEST_METHODS.contains(digestMethod)) {
            return "Disallowed digest method: " + digestMethod;
        }
        List<Transform> transforms = reference.getTransforms();
        if (transforms.size() > MAX_TRANSFORMS) {
            return "Too many transforms: " + transforms.size();
        }
        for (Transform transform : transforms) {
            if (!ALLOWED_TRANSFORMS.contains(transform.getAlgorithm())) {
                return "Disallowed transform: " + transform.getAlgorithm();
            }
        }

        String uri = reference.getURI();
        String uriRejection = checkReferenceUri(uri);
        if (uriRejection != null) {
            return uriRejection;
        }
        String id = uri.substring(1);
        List<Element> targets = new ArrayList<>(1);
        collectElementsById(document.getDocumentElement(), id, targets);
        if (targets.isEmpty()) {
            return "Signed element with Id='" + id + "' not found";
        }
        if (targets.size() > 1) {
            return "Multiple elements with Id='" + id + "' found (possible signature wrapping)";
        }
        Element target = targets.getFirst();
        if (target == signatureElement) {
            return "Signature cannot be its own signed business element";
        }
        String targetRejection = checkBusinessTarget(target, document);
        if (targetRejection != null) {
            return targetRejection;
        }
        target.setIdAttribute(ID_ATTRIBUTE, true);
        context.setIdAttributeNS(target, null, ID_ATTRIBUTE);
        // Simple fragments plus an explicit, unique ID binding keep the policy's target and
        // the provider's reference resolution aligned.
        if (document.getElementById(id) != target || context.getElementById(id) != target) {
            return "Reference does not resolve to the expected signed element";
        }
        return null;
    }

    private static @Nullable String checkBusinessTarget(Element target, Document document) {
        Element root = document.getDocumentElement();
        if (XMLSignature.XMLNS.equals(target.getNamespaceURI()) || target.getParentNode() != root) {
            return "Signed business element must be a direct child of the document root";
        }
        if (scanForIdAttribute(root) != target) {
            return "Reference must identify the first business element carrying an Id";
        }
        for (Node sibling = root.getFirstChild(); sibling != null; sibling = sibling.getNextSibling()) {
            if (sibling != target && sibling instanceof Element element
                    && Objects.equals(element.getNamespaceURI(), target.getNamespaceURI())
                    && Objects.equals(element.getLocalName(), target.getLocalName())) {
                return "Ambiguous business elements with the same qualified name";
            }
        }
        return null;
    }

    // ------------------------------------------------------------------
    // Parsing
    // ------------------------------------------------------------------

    private static long requirePositiveLimit(long limit) {
        if (limit <= 0) {
            throw new IllegalArgumentException("maxInputBytes must be positive");
        }
        return limit;
    }

    private static void checkInputSize(long size, long limit) {
        if (size > limit) {
            throw new XmlSignatureException("XML input exceeds maxInputBytes=" + limit);
        }
    }

    private static void checkInputSize(String xml, long limit) {
        if (limit == Long.MAX_VALUE) {
            return;
        }
        long bytes = 0;
        for (int i = 0; i < xml.length(); i++) {
            char c = xml.charAt(i);
            if (c < 0x80) {
                bytes++;
            } else if (c < 0x800) {
                bytes += 2;
            } else if (Character.isHighSurrogate(c) && i + 1 < xml.length()
                    && Character.isLowSurrogate(xml.charAt(i + 1))) {
                bytes += 4;
                i++;
            } else {
                // Malformed surrogate pairs are rejected by the parser, not silently encoded.
                bytes += 3;
            }
            checkInputSize(bytes, limit);
        }
    }

    private static final class LimitedInputStream extends InputStream {
        private final InputStream input;
        private final long limit;
        private long remaining;

        private LimitedInputStream(InputStream input, long limit) {
            this.input = input;
            this.limit = limit;
            this.remaining = limit;
        }

        @Override
        public int read() throws IOException {
            int value = input.read();
            if (value != -1) {
                if (remaining == 0) {
                    throw new XmlSignatureException("XML input exceeds maxInputBytes=" + limit);
                }
                remaining--;
            }
            return value;
        }

        @Override
        public int read(byte[] bytes, int offset, int length) throws IOException {
            Objects.checkFromIndexSize(offset, length, bytes.length);
            if (length == 0) {
                return 0;
            }
            int count = input.read(bytes, offset, (int) Math.min(length, remaining + 1));
            if (count > remaining) {
                throw new XmlSignatureException("XML input exceeds maxInputBytes=" + limit);
            }
            if (count > 0) {
                remaining -= count;
            }
            return count;
        }
    }

    static Document parse(InputStream input) throws IOException, SAXException {
        return parse(new InputSource(nonClosing(input)));
    }

    private static InputSource characterInput(String xml) {
        // A decoded byte-order mark is an encoding artifact, not XML character content.
        return new InputSource(new StringReader(xml.charAt(0) == '\uFEFF' ? xml.substring(1) : xml));
    }

    private static InputStream nonClosing(InputStream input) {
        return new FilterInputStream(input) {
            @Override
            public void close() {
                // Input belongs to the caller, including when the parser fails.
            }
        };
    }

    private static Document parse(InputSource input) throws IOException, SAXException {
        DocumentBuilder builder = PARSER_POOL.poll();
        if (builder == null) {
            builder = newDocumentBuilder();
        }
        try {
            Document document = builder.parse(input);
            if (!"1.0".equals(document.getXmlVersion())) {
                throw new XmlSignatureException("Only XML 1.0 documents are supported");
            }
            return document;
        } finally {
            builder.reset();
            PARSER_POOL.offer(builder);
        }
    }

    private static DocumentBuilder newDocumentBuilder() {
        try {
            return DOCUMENT_BUILDER_FACTORY.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            throw new XmlSignatureException("Failed to create DocumentBuilder", e);
        }
    }

    private static DocumentBuilderFactory createDocumentBuilderFactory() {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setIgnoringComments(true);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        try {
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            // XXE hardening: no DTDs, no external entities
            factory.setFeature(EXTERNAL_GENERAL_ENTITIES, false);
            factory.setFeature(EXTERNAL_PARAMETER_ENTITIES, false);
            factory.setFeature(DISALLOW_DOCTYPE_DECL, true);
        } catch (ParserConfigurationException e) {
            throw new XmlSignatureException("Error configuring DocumentBuilderFactory", e);
        }
        try {
            // Fiscal XMLs are small and fully traversed (C14N visits every node); the deferred
            // DOM only adds proxy indirection here. Optional: skipped on non-Xerces parsers.
            factory.setFeature(DEFER_NODE_EXPANSION, false);
        } catch (ParserConfigurationException ignored) {
            // feature unsupported by this JAXP implementation — harmless
        }
        return factory;
    }

    // ------------------------------------------------------------------
    // DOM lookups (replaces XPath/DTM; supports every fiscal document type)
    // ------------------------------------------------------------------

    private static Element findElementWithId(Document document) {
        Element found = scanForIdAttribute(document.getDocumentElement());
        if (found == null) {
            throw new XmlSignatureException("No element with an 'Id' attribute found; the XML is not signable");
        }
        return found;
    }

    private static boolean containsSignature(Element element) {
        if (XMLSignature.XMLNS.equals(element.getNamespaceURI()) && "Signature".equals(element.getLocalName())) {
            return true;
        }
        for (Node child = element.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child.getNodeType() == Node.ELEMENT_NODE && containsSignature((Element) child)) {
                return true;
            }
        }
        return false;
    }

    private static @Nullable Element scanForIdAttribute(Element element) {
        if (XMLSignature.XMLNS.equals(element.getNamespaceURI())) {
            return null;
        }
        if (element.hasAttribute(ID_ATTRIBUTE)) {
            return element;
        }
        for (Node child = element.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child.getNodeType() == Node.ELEMENT_NODE) {
                Element found = scanForIdAttribute((Element) child);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    /**
     * Collects every element whose {@code Id} attribute equals {@code id}. Verification walks the
     * whole tree instead of stopping at the first match so duplicate Ids — the classic setup for a
     * signature-wrapping attack — are detected and rejected.
     */
    private static void collectElementsById(Element element, String id, List<Element> matches) {
        if (id.equals(element.getAttribute(ID_ATTRIBUTE))) {
            matches.add(element);
        }
        for (Node child = element.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child.getNodeType() == Node.ELEMENT_NODE) {
                collectElementsById((Element) child, id, matches);
            }
        }
    }

    // ------------------------------------------------------------------
    // Static algorithm objects
    // ------------------------------------------------------------------

    private static DigestMethod newDigestMethod(String algorithmUri) {
        try {
            return SIGNATURE_FACTORY.newDigestMethod(algorithmUri, null);
        } catch (GeneralSecurityException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    /**
     * Extracts the public key from the X509Certificate embedded in KeyInfo, rejecting weak keys.
     */
    private static final class EmbeddedCertificateKeySelector extends KeySelector {

        @Override
        public KeySelectorResult select(@Nullable KeyInfo keyInfo, Purpose purpose, AlgorithmMethod method, XMLCryptoContext context) throws KeySelectorException {
            if (keyInfo == null) {
                throw new KeySelectorException("No KeyInfo found");
            }
            for (XMLStructure structure : keyInfo.getContent()) {
                if (structure instanceof X509Data x509Data) {
                    for (Object item : x509Data.getContent()) {
                        if (item instanceof X509Certificate certificate) {
                            PublicKey publicKey = certificate.getPublicKey();
                            if (!(publicKey instanceof RSAPublicKey rsa)) {
                                throw new KeySelectorException("XML signature requires an RSA certificate");
                            }
                            if (rsa.getModulus().bitLength() < MIN_RSA_KEY_BITS) {
                                throw new KeySelectorException("RSA key below " + MIN_RSA_KEY_BITS + " bits");
                            }
                            return () -> publicKey;
                        }
                    }
                }
            }
            throw new KeySelectorException("No X509Certificate found in KeyInfo");
        }
    }
}

