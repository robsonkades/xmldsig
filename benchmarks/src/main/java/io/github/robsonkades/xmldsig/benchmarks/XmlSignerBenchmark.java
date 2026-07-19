/*
 * Copyright 2026 Robson Kades
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.github.robsonkades.xmldsig.benchmarks;

import io.github.robsonkades.xmldsig.DocumentCustomizer;
import io.github.robsonkades.xmldsig.SigningCredential;
import io.github.robsonkades.xmldsig.VerificationResult;
import io.github.robsonkades.xmldsig.XmlMinify;
import io.github.robsonkades.xmldsig.XmlSigner;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

import java.io.InputStream;
import java.security.KeyStore;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

/**
 * Throughput of the {@code byte[]} hot path over a real NF-e sample.
 *
 * <p>Run from this directory (after {@code mvn install} on the library):
 * <pre>
 *   mvn package
 *   java -jar target/benchmarks.jar            # all benchmarks, defaults
 *   java -jar target/benchmarks.jar -t max     # saturate all cores
 * </pre>
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
@Fork(1)
@Warmup(iterations = 5, time = 2)
@Measurement(iterations = 5, time = 2)
public class XmlSignerBenchmark {

    private XmlSigner signer;
    private DocumentCustomizer minify;
    private byte[] nfe;
    private byte[] signedNfe;

    @Setup
    public void setup() throws Exception {
        char[] password = "changeit".toCharArray();
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = resource("/test-keystore.p12")) {
            keyStore.load(in, password);
        }
        signer = XmlSigner.of(SigningCredential.fromKeyStore(keyStore, password));
        minify = XmlMinify.minify();
        try (InputStream in = resource("/nfe.xml")) {
            nfe = in.readAllBytes();
        }
        signedNfe = signer.sign(nfe);
    }

    @Benchmark
    public byte[] sign() {
        return signer.sign(nfe);
    }

    @Benchmark
    public byte[] signMinified() {
        return signer.sign(nfe, minify);
    }

    @Benchmark
    public VerificationResult verifyIntegrity() {
        return XmlSigner.verifyIntegrity(signedNfe);
    }

    private static InputStream resource(String path) {
        return Objects.requireNonNull(
                XmlSignerBenchmark.class.getResourceAsStream(path), "missing resource: " + path);
    }
}
