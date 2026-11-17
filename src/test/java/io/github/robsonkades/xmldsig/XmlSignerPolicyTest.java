package io.github.robsonkades.xmldsig;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.XMLSignature;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class XmlSignerPolicyTest {
    private static SigningCredential credential;
    private static byte[] signed;

    @BeforeAll
    static void setup() throws Exception {
        var store = KeyStore.getInstance("PKCS12");
        try (InputStream in = XmlSignerPolicyTest.class.getResourceAsStream("/test-keystore.p12")) {
            store.load(in, "changeit".toCharArray());
        }
        credential = SigningCredential.fromKeyStore(store, "changeit".toCharArray());
        signed = XmlSigner.of(credential).sign("<root><data Id=\"x\">one</data></root>")
                .getBytes(StandardCharsets.UTF_8);
    }

    @ParameterizedTest
    @CsvSource({
            "SignatureMethod,http://www.w3.org/2001/04/xmldsig-more#rsa-sha512,signature method",
            "DigestMethod,http://www.w3.org/2001/04/xmlenc#sha512,digest method",
            "CanonicalizationMethod,http://www.w3.org/2001/10/xml-exc-c14n#,canonicalization method",
            "Transform,http://www.w3.org/2000/09/xmldsig#base64,transform",
            "SignatureMethod,urn:xmldsig-test:unknown,signature method",
            "DigestMethod,urn:xmldsig-test:unknown,digest method",
            "CanonicalizationMethod,urn:xmldsig-test:unknown,canonicalization method",
            "Transform,urn:xmldsig-test:unknown,transform"
    })
    void unsupportedAlgorithmsAreRejectedBeforeCryptographicValidation(String element, String algorithm, String reason)
            throws Exception {
        var doc = document();
        first(doc, element).setAttribute("Algorithm", algorithm);
        // A provider would reject this while unmarshalling. Policy must run before that.
        first(doc, "SignatureValue").setTextContent("not-base64!");
        assertPolicyRejection(doc, "Disallowed " + reason);
    }

    @Test
    void extraReferencesAreRejectedByPolicy() throws Exception {
        var doc = document();
        var reference = first(doc, "Reference");
        reference.getParentNode().appendChild(reference.cloneNode(true));
        first(doc, "SignatureValue").setTextContent("not-base64!");
        assertPolicyRejection(doc, "Expected exactly one Reference, found 2");
    }

    @Test
    void excessiveAllowedTransformsAreRejectedByPolicy() throws Exception {
        var doc = document();
        var transform = first(doc, "Transform");
        transform.getParentNode().appendChild(transform.cloneNode(true));
        transform.getParentNode().appendChild(transform.cloneNode(true));
        first(doc, "SignatureValue").setTextContent("not-base64!");
        assertPolicyRejection(doc, "Too many transforms: 4");
    }

    @Test
    void retrievalMethodCannotSupplyTheVerificationKey() throws Exception {
        var doc = document();
        var keyInfo = first(doc, "KeyInfo");
        keyInfo.setTextContent("");
        var retrieval = doc.createElementNS(XMLSignature.XMLNS, "RetrievalMethod");
        retrieval.setAttribute("URI", "urn:xmldsig-test:must-not-be-dereferenced");
        keyInfo.appendChild(retrieval);
        assertPolicyRejection(doc, "Disallowed KeyInfo content: RetrievalMethod");
    }

    @Test
    void retrievalMethodIsRejectedEvenAlongsideAnEmbeddedCertificate() throws Exception {
        var doc = document();
        var retrieval = doc.createElementNS(XMLSignature.XMLNS, "RetrievalMethod");
        retrieval.setAttribute("URI", "urn:xmldsig-test:must-not-be-dereferenced");
        first(doc, "KeyInfo").appendChild(retrieval);
        assertPolicyRejection(doc, "Disallowed KeyInfo content: RetrievalMethod");
    }

    @Test
    void algorithmParametersAreRejectedBeforeUnmarshalling() throws Exception {
        var doc = document();
        first(doc, "Transform").appendChild(doc.createElementNS(XMLSignature.XMLNS, "XPath"));
        first(doc, "SignatureValue").setTextContent("not-base64!");
        assertPolicyRejection(doc, "Parameters are not supported for Transform");
    }

    @ParameterizedTest
    @CsvSource({"Transform,Expected Transform elements", "DigestMethod,Expected optional Transforms"})
    void algorithmElementsMustUseTheSignatureNamespace(String element, String reason) throws Exception {
        var doc = document();
        var elements = doc.getElementsByTagNameNS(XMLSignature.XMLNS, element);
        // Exercise the second transform too: checking only the first sibling is insufficient.
        var renamed = (Element) doc.renameNode(elements.item(elements.getLength() - 1),
                "urn:xmldsig-test:foreign", "foreign:" + element);
        renamed.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:foreign", "urn:xmldsig-test:foreign");
        first(doc, "SignatureValue").setTextContent("not-base64!");
        assertPolicyRejection(doc, reason);
    }

    @Test
    void duplicateSignedInfoIsRejectedBeforeUnmarshalling() throws Exception {
        var doc = document();
        var signedInfo = first(doc, "SignedInfo");
        signedInfo.getParentNode().insertBefore(signedInfo.cloneNode(true), signedInfo);
        assertPolicyRejection(doc, "Expected SignedInfo, SignatureValue and KeyInfo");
    }

    @Test
    void embeddedCertificateIdentityMetadataRemainsSupported() throws Exception {
        var doc = document();
        var subject = doc.createElementNS(XMLSignature.XMLNS, "X509SubjectName");
        subject.setTextContent(credential.leafCertificate().getSubjectX500Principal().getName());
        first(doc, "X509Data").appendChild(subject);
        assertTrue(XmlSigner.verifyIntegrity(DomSerializer.writeToBytes(doc, 4096)).valid());
    }

    @Test
    void unsupportedAlgorithmsInAuxiliaryManifestsAreRejectedBeforeUnmarshalling() throws Exception {
        var doc = document();
        var object = doc.createElementNS(XMLSignature.XMLNS, "Object");
        var manifest = doc.createElementNS(XMLSignature.XMLNS, "Manifest");
        var reference = (Element) first(doc, "Reference").cloneNode(true);
        ((Element) reference.getElementsByTagNameNS(XMLSignature.XMLNS, "Transform").item(0))
                .setAttribute("Algorithm", "urn:xmldsig-test:unknown");
        manifest.appendChild(reference);
        object.appendChild(manifest);
        first(doc, "Signature").appendChild(object);
        assertPolicyRejection(doc, "Disallowed transform");
    }

    @Test
    void auxiliaryManifestIsNotDereferencedOrReportedAsAuthenticatedContent() throws Exception {
        var doc = document();
        var object = doc.createElementNS(XMLSignature.XMLNS, "Object");
        var manifest = doc.createElementNS(XMLSignature.XMLNS, "Manifest");
        var reference = (Element) first(doc, "Reference").cloneNode(true);
        reference.setAttribute("URI", "urn:xmldsig-test:must-not-be-dereferenced");
        manifest.appendChild(reference);
        object.appendChild(manifest);
        first(doc, "Signature").appendChild(object);
        // The sole SignedInfo reference still covers only <data>; validation must not resolve
        // this deliberately unresolvable, unsigned auxiliary reference.
        assertTrue(XmlSigner.verifyIntegrity(DomSerializer.writeToBytes(doc, 4096)).valid());
    }

    @ParameterizedTest
    @CsvSource({"weak-rsa, RSA key below 1024 bits", "ec, XML signature requires an RSA certificate"})
    void embeddedKeysMustBeRsaAndMeetMinimumSize(String fixture, String reason) throws Exception {
        var doc = document();
        first(doc, "X509Certificate").setTextContent(Base64.getEncoder().encodeToString(certificate(fixture).getEncoded()));
        assertKeyRejection(doc, reason);
    }

    @ParameterizedTest
    @CsvSource({"weak-rsa, RSA certificate key must be at least 1024 bits",
            "ec, XML signing requires an RSA private key and RSA certificate"})
    void signingCredentialsRejectUnsupportedPublicKeys(String fixture, String reason) throws Exception {
        var certificate = certificate(fixture);
        var error = assertThrows(CredentialException.class,
                () -> new SigningCredential(credential.privateKey(), List.of(certificate), null));
        assertEquals(reason, error.getMessage());
    }

    private static X509Certificate certificate(String fixture) throws Exception {
        try (InputStream in = XmlSignerPolicyTest.class.getResourceAsStream("/security/" + fixture + ".cer")) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
    }

    private static Document document() throws Exception {
        return XmlSigner.parse(new ByteArrayInputStream(signed));
    }

    private static Element first(Document doc, String name) {
        return (Element) doc.getElementsByTagNameNS(XMLSignature.XMLNS, name).item(0);
    }

    private static void assertPolicyRejection(Document doc, String reason) throws Exception {
        var result = XmlSigner.verifyIntegrity(DomSerializer.writeToBytes(doc, 4096));
        assertFalse(result.valid());
        assertTrue(result.detail().startsWith(reason), result::detail);
    }

    private static void assertKeyRejection(Document doc, String reason) throws Exception {
        byte[] bytes = DomSerializer.writeToBytes(doc, 4096);
        var error = assertThrows(XmlSignatureException.class, () -> XmlSigner.verifyIntegrity(bytes));
        Throwable cause = error;
        while (cause.getCause() != null) {
            cause = cause.getCause();
        }
        assertEquals(reason, cause.getMessage());
    }
}
