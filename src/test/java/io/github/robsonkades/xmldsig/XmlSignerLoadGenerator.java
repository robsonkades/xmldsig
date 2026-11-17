package io.github.robsonkades.xmldsig;

import java.io.InputStream;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletionService;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.LongAdder;

/**
 * Finite profiling workload, configured with positive {@code -Dthreads=N} and
 * {@code -DdurationSeconds=N} values. Defaults to available processors and 60 seconds.
 * Worker failures terminate the run with an error; this is not a latency benchmark.
 */
public class XmlSignerLoadGenerator {

    private static final char[] PASSWORD = "changeit".toCharArray();

    static void main() throws Exception {
        int threads = intProperty("threads", Runtime.getRuntime().availableProcessors());
        long durationSeconds = longProperty("durationSeconds", 60);
        validateConfiguration(threads, durationSeconds);

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = resourceStream("/test-keystore.p12")) {
            keyStore.load(in, PASSWORD);
        }

        var signer = XmlSigner.of(SigningCredential.fromKeyStore(keyStore, PASSWORD));
        byte[] xml;
        try (InputStream in = resourceStream("/fiscal/nfe.xml")) {
            xml = in.readAllBytes();
        }
        long totalSigned = run(signer, xml, threads, durationSeconds);
        System.out.printf("Done. Total signed: %d%n", totalSigned);
    }

    static long run(XmlSigner signer, byte[] xml, int threads, long durationSeconds)
            throws InterruptedException, ExecutionException {
        long durationNanos = validateConfiguration(threads, durationSeconds);
        long started = System.nanoTime();
        DocumentCustomizer minify = XmlMinify.minify();
        LongAdder totalSigned = new LongAdder();
        List<Future<Void>> workers = new ArrayList<>(threads);
        try (ExecutorService executor = Executors.newFixedThreadPool(
                threads, Thread.ofPlatform().name("signer-", 0).factory())) {
            CompletionService<Void> completions = new ExecutorCompletionService<>(executor);
            try {
                for (int i = 0; i < threads; i++) {
                    workers.add(completions.submit(() -> {
                        while (System.nanoTime() - started < durationNanos
                                && !Thread.currentThread().isInterrupted()) {
                            signer.sign(xml, minify);
                            totalSigned.increment();
                        }
                        return null;
                    }));
                }
                reportUntilDone(totalSigned, completions, threads, started);
            } finally {
                workers.forEach(worker -> worker.cancel(true));
            }
        }
        return totalSigned.sum();
    }

    private static void reportUntilDone(LongAdder totalSigned, CompletionService<Void> completions,
                                       int remaining, long started) throws InterruptedException, ExecutionException {
        Runtime runtime = Runtime.getRuntime();
        long lastCount = 0;
        long lastNanos = started;
        while (remaining > 0) {
            Future<Void> completed = completions.poll(2, TimeUnit.SECONDS);
            if (completed != null) {
                completed.get();
                remaining--;
            }
            long now = System.nanoTime();
            if (now - lastNanos >= TimeUnit.SECONDS.toNanos(2) || remaining == 0) {
                long count = totalSigned.sum();
                double perSecond = (count - lastCount) * 1_000_000_000.0 / (now - lastNanos);
                long usedMb = (runtime.totalMemory() - runtime.freeMemory()) / (1024 * 1024);
                System.out.printf("signed=%,d  rate=%,.0f/s  heapUsed=%dMB%n", count, perSecond, usedMb);
                lastCount = count;
                lastNanos = now;
            }
        }
    }

    private static long validateConfiguration(int threads, long durationSeconds) {
        if (threads < 1) {
            throw new IllegalArgumentException("threads must be positive");
        }
        if (durationSeconds < 1 || durationSeconds > Long.MAX_VALUE / 1_000_000_000L) {
            throw new IllegalArgumentException("durationSeconds must be positive and fit in nanoseconds");
        }
        return durationSeconds * 1_000_000_000L;
    }

    private static int intProperty(String name, int defaultValue) {
        String value = System.getProperty(name);
        return (value != null && !value.isBlank()) ? Integer.parseInt(value.trim()) : defaultValue;
    }

    private static long longProperty(String name, long defaultValue) {
        String value = System.getProperty(name);
        return (value != null && !value.isBlank()) ? Long.parseLong(value.trim()) : defaultValue;
    }

    private static InputStream resourceStream(String path) {
        return Objects.requireNonNull(XmlSignerLoadGenerator.class.getResourceAsStream(path),
                "missing test resource: " + path);
    }
}
