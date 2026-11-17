package io.github.robsonkades.xmldsig;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.w3c.dom.Document;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import static org.junit.jupiter.api.Assertions.*;

class XmlSignerContractTest {
    private static final String XML = "<root><data Id=\"x\"><value>one</value></data></root>";
    private static XmlSigner signer;

    @BeforeAll
    static void setup() throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = XmlSignerContractTest.class.getResourceAsStream("/test-keystore.p12")) {
            store.load(in, "changeit".toCharArray());
        }
        signer = XmlSigner.of(SigningCredential.fromKeyStore(store, "changeit".toCharArray()));
    }

    private static Document parse(byte[] bytes) throws Exception {
        return XmlSigner.parse(new ByteArrayInputStream(bytes));
    }

    @Test
    void processingInstructionSurvivesSigningAndReparse() {
        String signed = signer.sign(XML.replace("<value>", "<?audit stable?><value>"));
        assertTrue(signed.contains("<?audit stable?>"));
        assertTrue(XmlSigner.verifyIntegrity(signed).valid());
        assertFalse(XmlSigner.verifyIntegrity(signed.replace("audit stable", "audit changed")).valid());
    }

    @ParameterizedTest
    @ValueSource(strings = {"a\rb", "a]]>b", "a\r]]>b\uD83D\uDE80"})
    void customizedCdataPreservesCharacters(String value) throws Exception {
        byte[] signed = signer.sign(XML.getBytes(StandardCharsets.UTF_8), doc -> {
            var node = doc.getElementsByTagName("value").item(0);
            node.setTextContent("");
            node.appendChild(doc.createCDATASection(value));
        });
        assertEquals(value, parse(signed).getElementsByTagName("value").item(0).getTextContent());
        assertTrue(XmlSigner.verifyIntegrity(signed).valid());
    }

    @Test
    void customizerNamespaceDeclarationsAreEstablishedBeforeSigning() throws Exception {
        byte[] signed = signer.sign(XML.getBytes(StandardCharsets.UTF_8), doc -> {
            var child = doc.createElementNS("urn:extra", "e:extra");
            child.setAttributeNS("urn:attribute", "a:label", "ação");
            doc.getElementsByTagName("data").item(0).appendChild(child);
            doc.getElementsByTagName("data").item(0).appendChild(doc.createElement("plain"));
        });
        assertEquals(1, parse(signed).getElementsByTagNameNS("urn:extra", "extra").getLength());
        assertTrue(XmlSigner.verifyIntegrity(signed).valid());
    }

    @ParameterizedTest
    @ValueSource(strings = {"\uD800", "\uDC00", "\u0001"})
    void invalidCustomizedCharactersFailBeforeOutput(String value) {
        var out = new ByteArrayOutputStream();
        assertThrows(XmlSignatureException.class, () -> signer.sign(
                new ByteArrayInputStream(XML.getBytes(StandardCharsets.UTF_8)), out,
                doc -> doc.getElementsByTagName("value").item(0).setTextContent(value)));
        assertEquals(0, out.size());
    }

    @Test
    void xml11IsRejectedExplicitly() {
        assertThrows(XmlSignatureException.class, () -> signer.sign("<?xml version=\"1.1\"?>" + XML));
    }

    @Test
    void customizerWithAnUndeclaredPrefixFailsWithLibraryExceptionBeforeOutput() {
        var out = new ByteArrayOutputStream();
        assertThrows(XmlSignatureException.class, () -> signer.sign(
                new ByteArrayInputStream(XML.getBytes(StandardCharsets.UTF_8)), out,
                doc -> doc.getElementsByTagName("data").item(0).appendChild(doc.createElement("p:extra"))));
        assertEquals(0, out.size());
    }

    @Test
    void customizedUnqualifiedElementDoesNotInheritAnUnintendedNamespace() throws Exception {
        byte[] signed = signer.sign(XML.replace("<root>", "<root xmlns=\"urn:fiscal\">")
                .getBytes(StandardCharsets.UTF_8), doc -> doc.getElementsByTagNameNS("urn:fiscal", "data")
                .item(0).appendChild(doc.createElement("plain")));
        assertEquals(1, parse(signed).getElementsByTagNameNS(null, "plain").getLength());
        assertTrue(XmlSigner.verifyIntegrity(signed).valid());
    }

    @ParameterizedTest
    @ValueSource(strings = {"UTF-8", "ISO-8859-1", "UTF-16"})
    void stringInputPreservesUnicodeRegardlessOfEncodingDeclaration(String encoding) throws Exception {
        String signed = signer.sign("<?xml version=\"1.0\" encoding=\"" + encoding + "\"?>"
                + XML.replace("one", "ação 🚀"));
        assertEquals("ação 🚀", parse(signed.getBytes(StandardCharsets.UTF_8))
                .getElementsByTagName("value").item(0).getTextContent());
        assertTrue(XmlSigner.verifyIntegrity("<?xml version=\"1.0\" encoding=\"" + encoding + "\"?>" + signed).valid());
    }

    @Test
    void stringInputAcceptsADecodedLeadingByteOrderMark() {
        String signed = signer.sign("\uFEFF" + XML);
        assertTrue(XmlSigner.verifyIntegrity("\uFEFF" + signed).valid());
    }

    @Test
    void streamOwnershipAndFlushArePreservedOnSuccess() {
        var in = new TrackingInput(XML);
        var out = new TrackingOutput();
        signer.sign(in, out);
        assertFalse(in.closed);
        assertFalse(out.closed);
        assertTrue(out.flushed);
        assertTrue(XmlSigner.verifyIntegrity(out.toByteArray()).valid());
    }

    @Test
    void malformedInputDoesNotCloseCallerStreamsOrWriteOutput() {
        var in = new TrackingInput("<root>");
        var out = new TrackingOutput();
        assertThrows(XmlSignatureException.class, () -> signer.sign(in, out));
        assertFalse(in.closed);
        assertFalse(out.closed);
        assertEquals(0, out.size());
        assertTrue(XmlSigner.verifyIntegrity(signer.sign(XML)).valid(), "parser remains usable after an error");
    }

    @Test
    void outputFailureRetainsCauseAndDoesNotCloseStreams() {
        var in = new TrackingInput(XML);
        IOException failure = new IOException("write failed");
        boolean[] closed = {false};
        var out = new java.io.OutputStream() {
            @Override public void write(int value) throws IOException { throw failure; }
            @Override public void close() { closed[0] = true; }
        };
        var error = assertThrows(XmlSignatureException.class, () -> signer.sign(in, out));
        assertSame(failure, error.getCause());
        assertFalse(in.closed);
        assertFalse(closed[0]);
    }

    @Test
    void unsupportedDocumentShapesFailBeforeSigning() {
        for (String xml : new String[]{
                "<root Id=\"x\"><data/></root>",
                "<root><wrapper><data Id=\"x\"/></wrapper></root>",
                "<root><data Id=\"x\"/><other Id=\"x\"/></root>",
                "<root><data Id=\"x\"/><data Id=\"y\"/></root>",
                "<root><data Id=\"not a simple id\"/></root>"}) {
            assertThrows(XmlSignatureException.class, () -> signer.sign(xml), xml);
        }
    }

    @Test
    void verificationRejectsRelocatedSignatureAndAmbiguousBusinessElements() {
        String signed = signer.sign(XML);
        assertFalse(XmlSigner.verifyIntegrity("<envelope>" + signed + "</envelope>").valid());
        assertFalse(XmlSigner.verifyIntegrity(signed.replace("<data Id=", "<data>other</data><data Id=")).valid());
        assertFalse(XmlSigner.verifyIntegrity(signed.replace("</data>", "</data><data Id=\"y\"/>")).valid());
    }

    @Test
    void signatureItselfIsNotABusinessTarget() {
        String signed = signer.sign(XML).replace("<Signature xmlns=", "<Signature Id=\"self\" xmlns=")
                .replace("URI=\"#x\"", "URI=\"#self\"");
        VerificationResult result = XmlSigner.verifyIntegrity(signed);
        assertFalse(result.valid());
        assertTrue(result.detail().contains("own signed business element"), result.detail());
    }

    @ParameterizedTest
    @ValueSource(strings = {"#xpointer(id('x'))", "#x%20y", "https://example.invalid/document", ""})
    void onlySimpleLocalReferencesReachValidation(String uri) {
        String signed = signer.sign(XML).replace("URI=\"#x\"", "URI=\"" + uri + "\"");
        VerificationResult result = XmlSigner.verifyIntegrity(signed);
        assertFalse(result.valid());
        assertTrue(result.detail().startsWith("Reference URI must"), result.detail());
    }

    @Test
    void duplicateSignaturesAndDoctypeAreRejected() {
        String signed = signer.sign(XML);
        String signature = signed.substring(signed.indexOf("<Signature"), signed.indexOf("</Signature>") + 12);
        assertFalse(XmlSigner.verifyIntegrity(signed.replace("</root>", signature + "</root>")).valid());
        assertThrows(XmlSignatureException.class, () -> signer.sign("<!DOCTYPE root [<!ENTITY example 'value'>]>" + XML));
    }

    private static final class TrackingInput extends ByteArrayInputStream {
        boolean closed;
        TrackingInput(String xml) { super(xml.getBytes(StandardCharsets.UTF_8)); }
        @Override public void close() { closed = true; }
    }

    private static final class TrackingOutput extends ByteArrayOutputStream {
        boolean closed;
        boolean flushed;
        @Override public void close() { closed = true; }
        @Override public void flush() { flushed = true; }
    }
}
