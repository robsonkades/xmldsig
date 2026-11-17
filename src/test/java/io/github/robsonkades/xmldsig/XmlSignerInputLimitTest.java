package io.github.robsonkades.xmldsig;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import static org.junit.jupiter.api.Assertions.*;

class XmlSignerInputLimitTest {
    private static SigningCredential credential;

    @BeforeAll
    static void setup() throws Exception {
        var store = KeyStore.getInstance("PKCS12");
        try (InputStream in = XmlSignerInputLimitTest.class.getResourceAsStream("/test-keystore.p12")) {
            store.load(in, "changeit".toCharArray());
        }
        credential = SigningCredential.fromKeyStore(store, "changeit".toCharArray());
    }

    @ParameterizedTest
    @ValueSource(strings = {"one", "ação", "中文", "🚀"})
    void byteAndStringLimitsAgreeAtUtf8Boundary(String value) {
        String xml = "\uFEFF<root><data Id=\"x\">" + value + "</data></root>";
        byte[] bytes = xml.getBytes(StandardCharsets.UTF_8);
        var exact = XmlSigner.of(credential, SignatureAlgorithm.RSA_SHA256, bytes.length);
        assertTrue(XmlSigner.verifyIntegrity(exact.sign(bytes)).valid());
        assertTrue(XmlSigner.verifyIntegrity(exact.sign(xml)).valid());
        var smaller = XmlSigner.of(credential, bytes.length - 1);
        assertLimitFailure(() -> smaller.sign(bytes, doc -> fail("customizer must not run")));
        assertLimitFailure(() -> smaller.sign(xml, doc -> fail("customizer must not run")));
    }

    @Test
    void streamBoundaryPreservesOwnershipAndStopsBeforeOutput() {
        String xml = "<root><data Id=\"x\">ação 🚀</data></root>";
        byte[] bytes = xml.getBytes(StandardCharsets.UTF_8);
        var exact = XmlSigner.of(credential, bytes.length);
        var input = new TrackingInput(bytes);
        var output = new TrackingOutput();
        exact.sign(input, output);
        assertTrue(XmlSigner.verifyIntegrity(output.toByteArray()).valid());
        assertFalse(input.closed);
        assertFalse(output.closed);

        var oversized = new TrackingInput((xml + " ".repeat(10000)).getBytes(StandardCharsets.UTF_8));
        var rejectedOutput = new TrackingOutput();
        assertLimitFailure(() -> exact.sign(oversized, rejectedOutput, doc -> fail("customizer must not run")));
        assertEquals(bytes.length + 1, oversized.consumed());
        assertEquals(0, rejectedOutput.size());
        assertFalse(oversized.closed);
        assertFalse(rejectedOutput.closed);
        assertTrue(XmlSigner.verifyIntegrity(exact.sign(xml)).valid(), "parser can be reused after overflow");
    }

    @Test
    void verificationLimitsRunBeforeParsing() {
        String signed = XmlSigner.of(credential).sign("<root><data Id=\"x\">ação 🚀</data></root>");
        byte[] bytes = signed.getBytes(StandardCharsets.UTF_8);
        assertTrue(XmlSigner.verifyIntegrity(bytes, bytes.length).valid());
        assertTrue(XmlSigner.verifyIntegrity(signed, bytes.length).valid());
        assertLimitFailure(() -> XmlSigner.verifyIntegrity(bytes, bytes.length - 1));
        assertLimitFailure(() -> XmlSigner.verifyIntegrity(signed, bytes.length - 1));
        assertLimitFailure(() -> XmlSigner.verifyIntegrity("<malformed", 1));
    }

    @ParameterizedTest
    @ValueSource(longs = {0, -1, Long.MIN_VALUE})
    void nonpositiveLimitsAreRejected(long limit) {
        assertThrows(IllegalArgumentException.class, () -> XmlSigner.of(credential, limit));
        assertThrows(IllegalArgumentException.class, () -> XmlSigner.verifyIntegrity("<root/>", limit));
        assertThrows(IllegalArgumentException.class, () -> XmlSigner.verifyIntegrity(new byte[]{1}, limit));
    }

    private static void assertLimitFailure(org.junit.jupiter.api.function.Executable operation) {
        var error = assertThrows(XmlSignatureException.class, operation);
        assertTrue(error.getMessage().contains("maxInputBytes"), error::toString);
    }

    private static final class TrackingInput extends ByteArrayInputStream {
        boolean closed;
        TrackingInput(byte[] bytes) { super(bytes); }
        int consumed() { return pos; }
        @Override public void close() { closed = true; }
    }

    private static final class TrackingOutput extends ByteArrayOutputStream {
        boolean closed;
        @Override public void close() { closed = true; }
    }
}
