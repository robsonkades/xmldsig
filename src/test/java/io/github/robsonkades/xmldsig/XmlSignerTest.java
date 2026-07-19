package io.github.robsonkades.xmldsig;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XmlSignerTest {

    private static final char[] PASSWORD = "changeit".toCharArray();
    private static final String NS = "http://www.portalfiscal.inf.br/nfe";
    private static final String SAMPLE =
            "<NFe xmlns=\"" + NS + "\">"
            + "<infNFe Id=\"NFe35240112345678000190550010000000011000000017\">"
            + "<ide><cUF>35</cUF></ide>"
            + "</infNFe></NFe>";

    private static XmlSigner signer;

    @BeforeAll
    static void createSigner() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = XmlSignerTest.class.getResourceAsStream("/test-keystore.p12")) {
            keyStore.load(in, PASSWORD);
        }
        signer = XmlSigner.of(SigningCredential.fromKeyStore(keyStore, PASSWORD));
    }

    private static byte[] sampleBytes() {
        return SAMPLE.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    @DisplayName("signed document embeds a Signature element")
    void signedDocumentHasSignature() {
        String signed = new String(signer.sign(sampleBytes()), StandardCharsets.UTF_8);

        assertTrue(signed.contains("Signature"), signed);
        assertTrue(signed.contains("SignatureValue"), signed);
    }

    @Test
    @DisplayName("round-trip: a signed byte[] document passes integrity verification")
    void roundTripBytes() {
        byte[] signed = signer.sign(sampleBytes());

        VerificationResult result = XmlSigner.verifyIntegrity(signed);

        assertTrue(result.valid(), result.detail());
    }

    @Test
    @DisplayName("round-trip: the String overload signs and verifies with detail \"OK\"")
    void roundTripString() {
        String signed = signer.sign(SAMPLE);

        VerificationResult result = XmlSigner.verifyIntegrity(signed);

        assertTrue(result.valid());
        assertEquals("OK", result.detail());
    }

    @Test
    @DisplayName("round-trip: the stream overload signs and verifies")
    void roundTripStream() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        signer.sign(new ByteArrayInputStream(sampleBytes()), out);

        assertTrue(XmlSigner.verifyIntegrity(out.toByteArray()).valid());
    }

    @Test
    @DisplayName("verification fails when the signed content is tampered with")
    void tamperedContentFailsVerification() {
        String signed = signer.sign(SAMPLE);
        String tampered = signed.replace("<cUF>35</cUF>", "<cUF>36</cUF>");
        assertNotEquals(signed, tampered);

        VerificationResult result = XmlSigner.verifyIntegrity(tampered);

        assertFalse(result.valid());
    }

    @Test
    @DisplayName("verifyIntegrity rejects a document with duplicate Ids (signature wrapping)")
    void duplicateIdFailsVerification() {
        String signed = signer.sign(SAMPLE);
        String wrapped = signed.replace("</NFe>",
                "<Wrapper Id=\"NFe35240112345678000190550010000000011000000017\"/></NFe>");

        VerificationResult result = XmlSigner.verifyIntegrity(wrapped);

        assertFalse(result.valid());
        assertTrue(result.detail().contains("Multiple elements with Id"), result.detail());
    }

    @Test
    @DisplayName("customizer mutates the signed element before signing and still verifies")
    void customizerAppliedBeforeSigning() {
        DocumentCustomizer addAttribute = document -> {
            Element infNFe = (Element) document.getElementsByTagNameNS(NS, "infNFe").item(0);
            infNFe.setAttribute("versao", "4.00");
        };

        byte[] signed = signer.sign(sampleBytes(), addAttribute);
        String asString = new String(signed, StandardCharsets.UTF_8);

        assertTrue(asString.contains("versao=\"4.00\""), asString);
        assertTrue(XmlSigner.verifyIntegrity(signed).valid());
    }

    @Test
    @DisplayName("signing throws when no element carries an Id attribute")
    void signingWithoutIdThrows() {
        byte[] noId = "<root><child>x</child></root>".getBytes(StandardCharsets.UTF_8);

        assertThrows(XmlSignatureException.class, () -> signer.sign(noId));
    }

    @Test
    @DisplayName("signing rejects null input")
    void signingRejectsNull() {
        assertThrows(XmlSignatureException.class, () -> signer.sign((byte[]) null));
    }

    @Test
    @DisplayName("signing rejects empty input")
    void signingRejectsEmpty() {
        assertThrows(XmlSignatureException.class, () -> signer.sign(new byte[0]));
    }

    @Test
    @DisplayName("of rejects a null credential")
    void ofRejectsNull() {
        assertThrows(NullPointerException.class, () -> XmlSigner.of(null));
    }

    @Test
    @DisplayName("verifyIntegrity reports an unsigned document as invalid")
    void unsignedDocumentIsInvalid() {
        VerificationResult result = XmlSigner.verifyIntegrity(SAMPLE);

        assertFalse(result.valid());
        assertEquals("No Signature element found", result.detail());
    }

    @Test
    @DisplayName("verifyIntegrity rejects null input")
    void verifyRejectsNull() {
        assertThrows(XmlSignatureException.class, () -> XmlSigner.verifyIntegrity((byte[]) null));
    }
}
