package io.github.robsonkades.xmldsig;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class XmlSignerCanonicalizationTest {
    private static final String XML = "<root><data Id='x'>one<!-- unsigned comment -->two</data></root>";
    private static SigningCredential credential;

    @BeforeAll
    static void setup() throws Exception {
        var store = KeyStore.getInstance("PKCS12");
        try (InputStream in = XmlSignerCanonicalizationTest.class.getResourceAsStream("/test-keystore.p12")) {
            store.load(in, "changeit".toCharArray());
        }
        credential = SigningCredential.fromKeyStore(store, "changeit".toCharArray());
        // Initialize the library before the independent provider can initialize shared XML classes.
        XmlSigner.of(credential);
    }

    @ParameterizedTest
    @CsvSource({"true,false,canonicalization method", "false,true,transform"})
    void validJdkSignaturesWithCommentAlgorithmsAreExplicitlyOutsideTheProfile(
            boolean signedInfoComments, boolean referenceComments, String reason) throws Exception {
        byte[] xml = jdkSigned(signedInfoComments, referenceComments);
        assertTrue(new String(xml, StandardCharsets.UTF_8).contains("<!-- unsigned comment -->"));
        assertTrue(jdkValid(xml), "the independent signature must be cryptographically valid");
        var result = XmlSigner.verifyIntegrity(xml);
        assertFalse(result.valid());
        assertTrue(result.detail().startsWith("Disallowed " + reason), result::detail);
    }

    @Test
    void inclusiveWithoutCommentsInteroperatesWithJdkAndDetectsBusinessChanges() throws Exception {
        byte[] xml = jdkSigned(false, false);
        assertTrue(jdkValid(xml));
        assertTrue(XmlSigner.verifyIntegrity(xml).valid());
        String changedComment = new String(xml, StandardCharsets.UTF_8).replace("unsigned comment", "changed comment");
        assertTrue(jdkValid(changedComment.getBytes(StandardCharsets.UTF_8)));
        assertTrue(XmlSigner.verifyIntegrity(changedComment).valid(), "comments are explicitly unauthenticated");
        String changedData = changedComment.replace(">one", ">changed");
        assertFalse(jdkValid(changedData.getBytes(StandardCharsets.UTF_8)));
        assertFalse(XmlSigner.verifyIntegrity(changedData).valid());
    }

    @Test
    void signerOutputDropsCommentsAndRemainsValidForJdk() throws Exception {
        byte[] xml = XmlSigner.of(credential, SignatureAlgorithm.RSA_SHA256)
                .sign(XML.getBytes(StandardCharsets.UTF_8));
        assertFalse(new String(xml, StandardCharsets.UTF_8).contains("<!--"));
        assertTrue(jdkValid(xml));
    }

    private static byte[] jdkSigned(boolean signedInfoComments, boolean referenceComments) throws Exception {
        var doc = parse(XML.getBytes(StandardCharsets.UTF_8));
        var target = (Element) doc.getElementsByTagName("data").item(0);
        target.setIdAttribute("Id", true);
        var factory = XMLSignatureFactory.getInstance("DOM", "XMLDSig");
        var reference = factory.newReference("#x", factory.newDigestMethod(DigestMethod.SHA256, null),
                List.of(factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null),
                        factory.newTransform(referenceComments ? CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS
                                : CanonicalizationMethod.INCLUSIVE, (TransformParameterSpec) null)), null, null);
        var signedInfo = factory.newSignedInfo(factory.newCanonicalizationMethod(
                        signedInfoComments ? CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS
                                : CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
                factory.newSignatureMethod(SignatureMethod.RSA_SHA256, null), List.of(reference));
        var keyFactory = factory.getKeyInfoFactory();
        var keyInfo = keyFactory.newKeyInfo(List.of(keyFactory.newX509Data(List.of(credential.leafCertificate()))));
        factory.newXMLSignature(signedInfo, keyInfo).sign(new DOMSignContext(credential.privateKey(), doc.getDocumentElement()));
        var output = new ByteArrayOutputStream();
        // Preserve comments independently of the library's parser and serializer.
        TransformerFactory.newDefaultInstance().newTransformer().transform(new DOMSource(doc), new StreamResult(output));
        return output.toByteArray();
    }

    private static boolean jdkValid(byte[] xml) throws Exception {
        var doc = parse(xml);
        ((Element) doc.getElementsByTagName("data").item(0)).setIdAttribute("Id", true);
        var context = new DOMValidateContext(credential.leafCertificate().getPublicKey(),
                doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature").item(0));
        return XMLSignatureFactory.getInstance("DOM", "XMLDSig").unmarshalXMLSignature(context).validate(context);
    }

    private static Document parse(byte[] xml) throws Exception {
        return DocumentBuilderFactory.newDefaultNSInstance().newDocumentBuilder()
                .parse(new ByteArrayInputStream(xml));
    }
}
