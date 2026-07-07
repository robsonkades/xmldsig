package io.github.robsonkades.xmldsig;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SigningCredentialTest {

    private static final char[] PASSWORD = "changeit".toCharArray();

    private static PrivateKey key;
    private static X509Certificate certificate;

    @BeforeAll
    static void loadMaterial() throws Exception {
        KeyStore keyStore = loadKeyStore();
        key = (PrivateKey) keyStore.getKey("test", PASSWORD);
        certificate = (X509Certificate) keyStore.getCertificate("test");
    }

    private static KeyStore loadKeyStore() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = SigningCredentialTest.class.getResourceAsStream("/test-keystore.p12")) {
            keyStore.load(in, PASSWORD);
        }
        return keyStore;
    }

    @Test
    @DisplayName("builds a credential from a private key and certificate chain")
    void buildsValidCredential() {
        SigningCredential credential = new SigningCredential(key, List.of(certificate), "test");

        assertSame(key, credential.privateKey());
        assertEquals(List.of(certificate), credential.certificateChain());
        assertEquals("test", credential.alias());
    }

    @Test
    @DisplayName("rejects a null private key")
    void rejectsNullPrivateKey() {
        assertThrows(NullPointerException.class,
                () -> new SigningCredential(null, List.of(certificate), "test"));
    }

    @Test
    @DisplayName("rejects a null certificate chain")
    void rejectsNullChain() {
        assertThrows(NullPointerException.class,
                () -> new SigningCredential(key, null, "test"));
    }

    @Test
    @DisplayName("rejects an empty certificate chain with CredentialException")
    void rejectsEmptyChain() {
        assertThrows(CredentialException.class,
                () -> new SigningCredential(key, List.of(), "test"));
    }

    @Test
    @DisplayName("exposes the certificate chain as an immutable list")
    void chainIsImmutable() {
        SigningCredential credential = new SigningCredential(key, List.of(certificate), "test");

        assertThrows(UnsupportedOperationException.class,
                () -> credential.certificateChain().add(certificate));
    }

    @Test
    @DisplayName("defensively copies the certificate chain at construction")
    void defensivelyCopiesChain() {
        List<X509Certificate> mutable = new ArrayList<>();
        mutable.add(certificate);
        SigningCredential credential = new SigningCredential(key, mutable, "test");

        mutable.clear();

        assertEquals(1, credential.certificateChain().size());
    }

    @Test
    @DisplayName("leafCertificate returns the first certificate in the chain")
    void leafCertificateIsFirst() {
        SigningCredential credential = new SigningCredential(key, List.of(certificate), "test");

        assertSame(certificate, credential.leafCertificate());
    }

    @Test
    @DisplayName("isLikelyHardwareKey is false for a software RSA key")
    void softwareKeyIsNotHardware() {
        SigningCredential credential = new SigningCredential(key, List.of(certificate), "test");

        assertFalse(credential.isLikelyHardwareKey());
    }

    @Test
    @DisplayName("fromKeyStore loads the credential from an existing alias")
    void fromKeyStoreLoadsAlias() throws Exception {
        SigningCredential credential = SigningCredential.fromKeyStore(loadKeyStore(), PASSWORD);

        assertEquals("test", credential.alias());
        assertEquals(certificate, credential.leafCertificate());
    }

    @Test
    @DisplayName("fromKeyStore throws CredentialException for an unknown alias")
    void fromKeyStoreUnknownAlias() throws Exception {
        KeyStore keyStore = loadKeyStore();

        assertThrows(CredentialException.class,
                () -> SigningCredential.fromKeyStore(keyStore, PASSWORD, "does-not-exist"));
    }

    @Test
    @DisplayName("fromKeyStore throws CredentialException for a null KeyStore")
    void fromKeyStoreNullStore() {
        assertThrows(CredentialException.class,
                () -> SigningCredential.fromKeyStore(null, PASSWORD));
    }

    @Test
    @DisplayName("fromKeyStore throws CredentialException for a wrong password")
    void fromKeyStoreWrongPassword() throws Exception {
        KeyStore keyStore = loadKeyStore();

        assertThrows(CredentialException.class,
                () -> SigningCredential.fromKeyStore(keyStore, "wrong".toCharArray()));
    }
}
