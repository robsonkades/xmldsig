package io.github.robsonkades.xmldsig;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class XmlSignerLoadGenerator {

    private static final char[] PASSWORD = "changeit".toCharArray();

    static void main() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, InterruptedException {
        int threads = intProperty("threads", Runtime.getRuntime().availableProcessors());
        long durationSeconds = longProperty("durationSeconds", 0);

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = XmlSignerTest.class.getResourceAsStream("/test-keystore.p12")) {
            keyStore.load(in, PASSWORD);
        }

        var signer = XmlSigner.of(SigningCredential.fromKeyStore(keyStore, PASSWORD));
        long deadline = durationSeconds > 0 ? System.nanoTime() + durationSeconds * 1_000_000_000L : Long.MAX_VALUE;

        byte[] resource = resource("/fiscal/nfe.xml");

        AtomicLong totalSigned = new AtomicLong();
        Thread[] workers = new Thread[threads];
        for (int i = 0; i < threads; i++) {
            workers[i] = new Thread(() -> {
                while (System.nanoTime() < deadline) {
                    signer.sign(resource, document -> {
                        XmlMinify.minify().customize(document);
                    });
                    totalSigned.incrementAndGet();
                }
            }, "signer-" + i);
            workers[i].start();
        }

        reportUntilDone(totalSigned, workers, deadline);

        for (Thread worker : workers) {
            worker.join();
        }
        System.out.printf("Done. Total signed: %d%n", totalSigned.get());
    }

    private static void reportUntilDone(AtomicLong totalSigned, Thread[] workers, long deadline) throws InterruptedException {
        Runtime runtime = Runtime.getRuntime();
        long lastCount = 0;
        long lastNanos = System.nanoTime();
        while (System.nanoTime() < deadline && anyAlive(workers)) {
            Thread.sleep(2000);
            long now = System.nanoTime();
            long count = totalSigned.get();
            double perSecond = (count - lastCount) * 1_000_000_000.0 / (now - lastNanos);
            long usedMb = (runtime.totalMemory() - runtime.freeMemory()) / (1024 * 1024);
            System.out.printf("signed=%,d  rate=%,.0f/s  heapUsed=%dMB%n", count, perSecond, usedMb);
            lastCount = count;
            lastNanos = now;
        }
    }

    private static boolean anyAlive(Thread[] workers) {
        for (Thread worker : workers) {
            if (worker.isAlive()) {
                return true;
            }
        }
        return false;
    }

    private static int intProperty(String name, int defaultValue) {
        String value = System.getProperty(name);
        return (value != null && !value.isBlank()) ? Integer.parseInt(value.trim()) : defaultValue;
    }

    private static long longProperty(String name, long defaultValue) {
        String value = System.getProperty(name);
        return (value != null && !value.isBlank()) ? Long.parseLong(value.trim()) : defaultValue;
    }

    private static byte[] resource(String path) throws IOException {
        try (InputStream in = XmlSignerLoadGenerator.class.getResourceAsStream(path)) {
            assertNotNull(in, "missing test resource: " + path);
            return in.readAllBytes();
        }
    }
}
