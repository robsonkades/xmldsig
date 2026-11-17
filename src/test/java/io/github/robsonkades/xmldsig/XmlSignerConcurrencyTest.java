package io.github.robsonkades.xmldsig;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.w3c.dom.Element;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XmlSignerConcurrencyTest {

    private static final String NS = "urn:xmldsig:concurrency-test";
    private static final int WORKERS = 16;
    private static XmlSigner sha1Signer;
    private static XmlSigner sha256Signer;
    private static PublicKey publicKey;

    @BeforeAll
    static void createSharedSigners() throws Exception {
        char[] password = "changeit".toCharArray();
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = XmlSignerConcurrencyTest.class.getResourceAsStream("/test-keystore.p12")) {
            assertNotNull(in);
            keyStore.load(in, password);
        }
        SigningCredential credential = SigningCredential.fromKeyStore(keyStore, password);
        publicKey = credential.leafCertificate().getPublicKey();
        sha1Signer = XmlSigner.of(credential, SignatureAlgorithm.RSA_SHA1);
        sha256Signer = XmlSigner.of(credential, SignatureAlgorithm.RSA_SHA256);
    }

    @ParameterizedTest(name = "shared signers, virtual threads = {0}")
    @ValueSource(booleans = {false, true})
    @Timeout(30)
    void sharedSignersPreserveEveryRequestAndInteroperateWithJdk(boolean virtual) throws Exception {
        ExecutorService executor = virtual
                ? Executors.newVirtualThreadPerTaskExecutor() : Executors.newFixedThreadPool(WORKERS);
        CountDownLatch ready = new CountDownLatch(WORKERS);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Void>> workers = new ArrayList<>();
        try {
            for (int worker = 0; worker < WORKERS; worker++) {
                int workerId = worker;
                workers.add(executor.submit(() -> {
                    var parser = DocumentBuilderFactory.newDefaultNSInstance().newDocumentBuilder();
                    var verifier = XMLSignatureFactory.getInstance("DOM", "XMLDSig");
                    ready.countDown();
                    start.await();
                    for (int operation = 0; operation < 10; operation++) {
                        String id = "N" + workerId + "_" + operation;
                        String text = id + " ação € 😀";
                        String xml = "<root xmlns='" + NS + "'><item Id='" + id + "'>" + text + "</item></root>";
                        XmlSigner signer = operation % 2 == 0 ? sha1Signer : sha256Signer;
                        byte[] signed = signer.sign(xml.getBytes(StandardCharsets.UTF_8));
                        VerificationResult result = XmlSigner.verifyIntegrity(signed);
                        assertTrue(result.valid(), () -> id + ": " + result.detail());

                        var document = parser.parse(new ByteArrayInputStream(signed));
                        Element target = (Element) document.getElementsByTagNameNS(NS, "item").item(0);
                        assertEquals(id, target.getAttribute("Id"));
                        assertEquals(text, target.getTextContent());
                        target.setIdAttribute("Id", true);
                        var signatures = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
                        assertEquals(1, signatures.getLength());
                        var context = new DOMValidateContext(publicKey, signatures.item(0));
                        // Required only for the explicitly exercised legacy RSA-SHA1 profile.
                        context.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.FALSE);
                        var signature = verifier.unmarshalXMLSignature(context);
                        assertEquals("#" + id, signature.getSignedInfo().getReferences().getFirst().getURI());
                        assertTrue(signature.validate(context), () -> "JDK verification failed: " + id);
                    }
                    return null;
                }));
            }
            assertTrue(ready.await(10, TimeUnit.SECONDS), "workers did not reach the start barrier");
            start.countDown();
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
            for (Future<Void> worker : workers) {
                worker.get(Math.max(1, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
            }
        } finally {
            start.countDown();
            workers.forEach(worker -> worker.cancel(true));
            executor.shutdownNow();
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS), "workers did not terminate");
        }
    }
}
