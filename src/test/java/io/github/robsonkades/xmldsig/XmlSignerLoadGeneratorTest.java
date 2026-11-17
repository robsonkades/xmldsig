package io.github.robsonkades.xmldsig;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.concurrent.ExecutionException;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class XmlSignerLoadGeneratorTest {

    private static XmlSigner signer;

    @BeforeAll
    static void createSigner() throws Exception {
        char[] password = "changeit".toCharArray();
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = XmlSignerLoadGeneratorTest.class.getResourceAsStream("/test-keystore.p12")) {
            assertNotNull(in);
            keyStore.load(in, password);
        }
        signer = XmlSigner.of(SigningCredential.fromKeyStore(keyStore, password));
    }

    @Test
    @Timeout(5)
    void workerFailureFailsTheRun() {
        byte[] unsigned = "<root><child/></root>".getBytes(StandardCharsets.UTF_8);
        ExecutionException failure = assertThrows(ExecutionException.class,
                () -> XmlSignerLoadGenerator.run(signer, unsigned, 2, 60));
        assertInstanceOf(XmlSignatureException.class, failure.getCause());
    }

    @ParameterizedTest
    @CsvSource({"0, 1", "-1, 1", "1, 0", "1, -1", "1, 9223372037"})
    void rejectsInvalidOrOverflowingConfiguration(int threads, long seconds) {
        assertThrows(IllegalArgumentException.class,
                () -> XmlSignerLoadGenerator.run(signer, new byte[0], threads, seconds));
    }
}
