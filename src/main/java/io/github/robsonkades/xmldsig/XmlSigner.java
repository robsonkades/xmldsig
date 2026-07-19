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
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

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
import java.io.OutputStream;
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
 * expected to be a direct child of that root, so the signature becomes its sibling. This matches
 * the SEFAZ layouts (NF-e/NFC-e/CT-e/MDF-e and their events) and the national NFS-e model. A layout
 * that nests the {@code Id} element deeper (such as the ABRASF municipal NFS-e) still signs, but
 * {@link #verifyIntegrity(byte[])} then rejects it as a possible signature-wrapping attack.
 *
 * <p><b>Performance notes:</b>
 * <ul>
 *   <li>Prefer the {@code byte[]}/stream overloads; the {@code String} overloads pay two full
 *       UTF-8 conversions.</li>
 *   <li>{@link DocumentBuilder} instances are pooled in a small bounded queue — safe and
 *       effective under both platform and virtual threads (a {@code ThreadLocal} cache would be
 *       useless under virtual threads).</li>
 *   <li>The element-with-Id lookup is a direct DOM walk (no XPath/DTM), supporting any fiscal
 *       document type ({@code NFe...}, {@code CTe...}, {@code MDFe...}, {@code ID...} ids).</li>
 *   <li>Serialization uses {@link DomSerializer}; XML comments are always dropped (they are
 *       excluded from inclusive C14N, so signatures are unaffected).</li>
 * </ul>
 *
 * <p><b>Algorithms:</b> RSA-SHA1 with SHA-1 digests, as fixed by the SEFAZ signature schema
 * ({@code xmldsig-core-schema_v1.01.xsd}) for NF-e/CT-e/MDF-e. SHA-1 is cryptographically weak,
 * but the algorithm is mandated by the fiscal layout; trust is established by the ICP-Brasil
 * chain and SEFAZ-side validation, not by the digest strength.
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
    private static final DigestMethod SHA1_DIGEST_METHOD = newDigestMethod();

    private static final DocumentBuilderFactory DOCUMENT_BUILDER_FACTORY = createDocumentBuilderFactory();
    private static final int PARSER_POOL_MAX = Math.max(8, Runtime.getRuntime().availableProcessors() * 2);
    // ArrayBlockingQueue used purely non-blockingly (poll/offer): intrinsically bounded, and its
    // size check is O(1) — ConcurrentLinkedQueue.size() traverses the whole queue.
    private static final ArrayBlockingQueue<DocumentBuilder> PARSER_POOL = new ArrayBlockingQueue<>(PARSER_POOL_MAX);

    private static final KeySelector EMBEDDED_CERTIFICATE_KEY_SELECTOR = new EmbeddedCertificateKeySelector();
    private static final Set<String> ALLOWED_CANONICALIZATION = Set.of(CanonicalizationMethod.INCLUSIVE, CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS);
    private static final Set<String> ALLOWED_SIGNATURE_METHODS = Set.of(SignatureMethod.RSA_SHA1, SignatureMethod.RSA_SHA256);
    private static final Set<String> ALLOWED_DIGEST_METHODS = Set.of(DigestMethod.SHA1, DigestMethod.SHA256);
    private static final Set<String> ALLOWED_TRANSFORMS = Set.of(Transform.ENVELOPED, CanonicalizationMethod.INCLUSIVE, CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS);
    private static final int MAX_TRANSFORMS = 3;

    private final PrivateKey privateKey;
    private final KeyInfo keyInfo;

    private XmlSigner(final SigningCredential credential) {
        this.privateKey = credential.privateKey();
        KeyInfoFactory keyInfoFactory = SIGNATURE_FACTORY.getKeyInfoFactory();
        X509Data x509Data = keyInfoFactory.newX509Data(List.of(credential.leafCertificate()));
        this.keyInfo = keyInfoFactory.newKeyInfo(List.of(x509Data));
    }

    /**
     * Creates a signer for the given credential. Create once per certificate and share.
     *
     * @param credential the signing material; must not be {@code null}
     * @return an immutable, thread-safe signer bound to the credential
     */
    public static XmlSigner of(SigningCredential credential) {
        return new XmlSigner(Objects.requireNonNull(credential, "credential must not be null"));
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
     * Convenience {@code String} variant. Costs two extra full UTF-8 conversions; prefer
     * {@link #sign(byte[])} on hot paths.
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
        return new String(doSign(xml.getBytes(StandardCharsets.UTF_8), customizer), StandardCharsets.UTF_8);
    }

    private byte[] doSign(byte[] xml, @Nullable DocumentCustomizer customizer) {
        if (xml == null || xml.length == 0) {
            throw new XmlSignatureException("XML must not be null or empty");
        }
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
            Document document = parseCustomizeSign(input, customizer);
            DomSerializer.write(document, output);
        } catch (IOException e) {
            throw new XmlSignatureException("XML signing failed", e);
        }
    }

    private Document parseCustomizeSign(InputStream input, @Nullable DocumentCustomizer customizer) {
        try {
            Document document = parse(input);
            if (customizer != null) {
                customizer.customize(document);
            }
            signInPlace(document);
            return document;
        } catch (SAXException e) {
            throw new XmlSignatureException("Malformed XML content", e);
        } catch (GeneralSecurityException | MarshalException | XMLSignatureException | IOException e) {
            throw new XmlSignatureException("XML signing failed", e);
        }
    }

    private void signInPlace(Document document) throws GeneralSecurityException, MarshalException, XMLSignatureException {
        Element target = findElementWithId(document);
        String id = target.getAttribute(ID_ATTRIBUTE);
        if (id.isBlank()) {
            throw new XmlSignatureException("Signable element has a blank Id attribute");
        }
        target.setIdAttribute(ID_ATTRIBUTE, true);

        Reference reference = SIGNATURE_FACTORY.newReference(
                "#" + id,
                SHA1_DIGEST_METHOD,
                List.of(SIGNATURE_FACTORY.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null),
                        SIGNATURE_FACTORY.newTransform(CanonicalizationMethod.INCLUSIVE,
                                (TransformParameterSpec) null)),
                null,
                null);

        SignedInfo signedInfo = SIGNATURE_FACTORY.newSignedInfo(
                SIGNATURE_FACTORY.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE,
                        (C14NMethodParameterSpec) null),
                SIGNATURE_FACTORY.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
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
     *
     * <p><b>This does not establish trust.</b> Any attacker can re-sign a tampered document with
     * their own certificate and pass this check. Authenticity requires validating the certificate
     * chain against ICP-Brasil trust anchors, which SEFAZ performs on submission.
     *
     * @param xml the signed UTF-8 encoded XML document; must not be {@code null} or empty
     * @return the verification outcome, with a human-readable reason when invalid
     */
    public static VerificationResult verifyIntegrity(byte[] xml) {
        if (xml == null || xml.length == 0) {
            throw new XmlSignatureException("XML must not be null or empty");
        }
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
        if (xml == null || xml.isBlank()) {
            throw new XmlSignatureException("XML must not be null or empty");
        }
        return verifyIntegrity(xml.getBytes(StandardCharsets.UTF_8));
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

        DOMValidateContext context = new DOMValidateContext(EMBEDDED_CERTIFICATE_KEY_SELECTOR, signatureElement);
        // SEFAZ mandates RSA-SHA1, which the generic JDK/Santuario secure-validation blacklist
        // rejects on modern JDKs. The blacklist is disabled and replaced by the stricter
        // whitelist enforced in checkSignaturePolicy (fixed algorithms, single same-document
        // reference, bounded transforms, minimum RSA key size).
        context.setProperty(ORG_JCP_XML_DSIG_SECURE_VALIDATION, Boolean.FALSE);

        try {
            XMLSignature signature = SIGNATURE_FACTORY.unmarshalXMLSignature(context);
            String rejection = checkSignaturePolicy(signature, signatureElement, document);
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
     * Returns a rejection reason, or {@code null} if the signature passes the structural policy.
     * As a side effect, registers the signed element's Id for reference dereferencing.
     */
    private static @Nullable String checkSignaturePolicy(XMLSignature signature, Element signatureElement, Document document) {
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
        if (uri == null || uri.length() < 2 || uri.charAt(0) != '#') {
            return "Reference URI must be a same-document Id reference";
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
        if (signatureElement.getParentNode() != target.getParentNode()) {
            return "Signature is not a sibling of the signed element (possible signature wrapping)";
        }
        target.setIdAttribute(ID_ATTRIBUTE, true);
        return null;
    }

    // ------------------------------------------------------------------
    // Parsing
    // ------------------------------------------------------------------

    static Document parse(InputStream input) throws IOException, SAXException {
        DocumentBuilder builder = PARSER_POOL.poll();
        if (builder == null) {
            builder = newDocumentBuilder();
        }
        try {
            return builder.parse(input);
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

    private static @Nullable Element scanForIdAttribute(Element element) {
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

    private static DigestMethod newDigestMethod() {
        try {
            return SIGNATURE_FACTORY.newDigestMethod(DigestMethod.SHA1, null);
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
                            if (publicKey instanceof RSAPublicKey rsa
                                    && rsa.getModulus().bitLength() < MIN_RSA_KEY_BITS) {
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

