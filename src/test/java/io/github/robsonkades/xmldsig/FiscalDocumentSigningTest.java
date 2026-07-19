package io.github.robsonkades.xmldsig;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Signs and verifies realistic mocks of every supported Brazilian fiscal document type. Each mock
 * places the {@code Id}-bearing element as a direct child of the document root — the structure the
 * signer supports (the signature is inserted at the root as a sibling of the signed element).
 */
class FiscalDocumentSigningTest {

    private static final char[] PASSWORD = "changeit".toCharArray();

    private static XmlSigner signer;

    @BeforeAll
    static void createSigner() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = FiscalDocumentSigningTest.class.getResourceAsStream("/test-keystore.p12")) {
            keyStore.load(in, PASSWORD);
        }
        signer = XmlSigner.of(SigningCredential.fromKeyStore(keyStore, PASSWORD));
    }

    private static byte[] resource(String path) throws IOException {
        try (InputStream in = FiscalDocumentSigningTest.class.getResourceAsStream(path)) {
            assertNotNull(in, "missing test resource: " + path);
            return in.readAllBytes();
        }
    }

    @ParameterizedTest(name = "{0}")
    @DisplayName("signs and verifies each fiscal document type")
    @CsvSource({
            "NF-e model 55, /fiscal/nfe.xml",
            "NFC-e model 65, /fiscal/nfce.xml",
            "CT-e, /fiscal/cte.xml",
            "MDF-e, /fiscal/mdfe.xml",
            "NFS-e national, /fiscal/nfse.xml",
            "NF-e event, /fiscal/evento-nfe.xml"
    })
    void signsAndVerifies(String label, String path) throws IOException {
        byte[] signed = signer.sign(resource(path), document -> {
            XmlMinify.minify().customize(document);
        });

        assertTrue(new String(signed, StandardCharsets.UTF_8).contains("Signature"), label);

        VerificationResult result = XmlSigner.verifyIntegrity(signed);
        assertTrue(result.valid(), () -> label + ": " + result.detail());
    }

    @Test
    @DisplayName("signs an event whose Id uses the \"ID\" prefix instead of the access key")
    void signsEventWithIdPrefix() throws IOException {
        byte[] signed = signer.sign(resource("/fiscal/evento-nfe.xml"));

        assertTrue(XmlSigner.verifyIntegrity(signed).valid());
    }

    @Test
    @DisplayName("preserves the NFC-e qrCode CDATA section through the signing pipeline")
    void preservesNfceQrCodeCdata() throws IOException {
        byte[] signed = signer.sign(resource("/fiscal/nfce.xml"));
        String asString = new String(signed, StandardCharsets.UTF_8);

        assertTrue(asString.contains("<![CDATA[https://"), asString);
        assertTrue(asString.contains("</qrCode>"), asString);
        assertTrue(XmlSigner.verifyIntegrity(signed).valid());
    }
}
