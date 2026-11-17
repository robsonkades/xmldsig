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

// Lives in the library package (not .benchmarks) to reach the package-private stage APIs
// (XmlSigner.parse, DomSerializer). The shaded benchmark jar runs on the classpath, where the
// split package is legal.
package io.github.robsonkades.xmldsig;

import org.apache.xml.security.c14n.Canonicalizer;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.crypto.dsig.XMLSignature;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

/**
 * Representative operations from the signing pipeline — parse, reference C14N, SHA-1 digest,
 * RSA over SignedInfo, and serialization of the signed document — plus the full pipeline.
 * The isolated measurements omit orchestration and must not be added to predict pipeline cost.
 *
 * <p>{@code detItems} controls document size: 1 item ≈ 0.8 KB (minimal event-like doc),
 * 100 items ≈ 35 KB (large invoice), 990 items ≈ 350 KB (legal maximum for one NF-e).
 *
 * <p>Run from this directory (after {@code mvn install} on the library):
 * <pre>
 *   mvn package -Dxmldsig.version=VERSION  # replace VERSION with the installed library version
 *   java -jar target/benchmarks.jar Stage -prof gc
 * </pre>
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@State(Scope.Thread)
@Fork(1)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
public class XmlSignerStageBenchmark {

    @Param({"1", "100", "990"})
    int detItems;

    private XmlSigner signer;
    private PrivateKey privateKey;
    private byte[] xml;
    private Element referenceTarget;
    private Document signedDocument;
    private byte[] canonicalReference;
    private byte[] canonicalSignedInfo;

    @Setup
    public void setup() throws Exception {
        char[] password = "changeit".toCharArray();
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = resource("/test-keystore.p12")) {
            keyStore.load(in, password);
        }
        SigningCredential credential = SigningCredential.fromKeyStore(keyStore, password);
        signer = XmlSigner.of(credential);
        privateKey = credential.privateKey();

        xml = syntheticNfe(detItems);
        byte[] signedXml = signer.sign(xml);
        VerificationResult result = XmlSigner.verifyIntegrity(signedXml);
        if (!result.valid()) {
            throw new IllegalStateException("Invalid benchmark signature: " + result.detail());
        }
        signedDocument = XmlSigner.parse(new ByteArrayInputStream(signedXml));
        referenceTarget = (Element) signedDocument.getElementsByTagNameNS(
                "http://www.portalfiscal.inf.br/nfe", "infNFe").item(0);
        Element signedInfo = (Element) signedDocument.getElementsByTagNameNS(
                XMLSignature.XMLNS, "SignedInfo").item(0);
        canonicalReference = canonicalize(referenceTarget, xml.length + 1024);
        canonicalSignedInfo = canonicalize(signedInfo, 1024);

        byte[] expectedDigest = Base64.getDecoder().decode(signedDocument.getElementsByTagNameNS(
                XMLSignature.XMLNS, "DigestValue").item(0).getTextContent());
        if (!MessageDigest.isEqual(expectedDigest, sha1Digest())) {
            throw new IllegalStateException("Benchmark C14N differs from the signed reference");
        }
        Signature verifier = Signature.getInstance("SHA1withRSA");
        verifier.initVerify(credential.leafCertificate());
        verifier.update(canonicalSignedInfo);
        byte[] signatureValue = Base64.getDecoder().decode(signedDocument.getElementsByTagNameNS(
                XMLSignature.XMLNS, "SignatureValue").item(0).getTextContent());
        if (!verifier.verify(signatureValue)) {
            throw new IllegalStateException("Benchmark SignedInfo differs from the signed bytes");
        }
    }

    // ------------------------------------------------------------------
    // Isolated stages
    // ------------------------------------------------------------------

    @Benchmark
    public Document parse() throws Exception {
        return XmlSigner.parse(new ByteArrayInputStream(xml));
    }

    /**
     * Inclusive C14N over the referenced infNFe subtree. The enveloped transform has no signature
     * to remove here because Signature is a sibling of infNFe.
     */
    @Benchmark
    public byte[] c14n() throws Exception {
        return canonicalize(referenceTarget, xml.length + 1024);
    }

    /** Digest floor: SHA-1 over the canonical bytes (what DOMReference computes). */
    @Benchmark
    public byte[] sha1Digest() throws Exception {
        return MessageDigest.getInstance("SHA-1").digest(canonicalReference);
    }

    /**
     * RSA-SHA1 over the actual canonicalized SignedInfo, whose size is independent of detItems.
     */
    @Benchmark
    public byte[] rsaSha1Sign() throws Exception {
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(privateKey);
        signature.update(canonicalSignedInfo);
        return signature.sign();
    }

    @Benchmark
    public byte[] serialize() throws Exception {
        return DomSerializer.writeToBytes(signedDocument, xml.length + 4096);
    }

    // ------------------------------------------------------------------
    // Full pipeline (parse + build signature + C14N + digest + sign + serialize)
    // ------------------------------------------------------------------

    @Benchmark
    public byte[] pipeline() {
        return signer.sign(xml);
    }

    // ------------------------------------------------------------------

    private static byte[] canonicalize(Element element, int sizeHint) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream(sizeHint);
        Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS)
                .canonicalizeSubtree(element, out);
        return out.toByteArray();
    }

    private static InputStream resource(String path) {
        return Objects.requireNonNull(
                XmlSignerStageBenchmark.class.getResourceAsStream(path), "missing resource: " + path);
    }

    private static byte[] syntheticNfe(int detItems) {
        StringBuilder sb = new StringBuilder(detItems * 360 + 1024);
        sb.append("<NFe xmlns=\"http://www.portalfiscal.inf.br/nfe\">")
                .append("<infNFe Id=\"NFe35150300822602000124550010009923461099234656\" versao=\"4.00\">")
                .append("<ide><cUF>35</cUF><natOp>VENDA DE MERCADORIA</natOp><mod>55</mod>")
                .append("<serie>1</serie><nNF>992346</nNF><tpAmb>2</tpAmb></ide>")
                .append("<emit><CNPJ>00822602000124</CNPJ><xNome>EMPRESA DEMONSTRACAO LTDA</xNome></emit>")
                .append("<dest><CNPJ>99999999000191</CNPJ><xNome>CLIENTE DEMONSTRACAO SA</xNome></dest>");
        for (int i = 1; i <= detItems; i++) {
            sb.append("<det nItem=\"").append(i).append("\">")
                    .append("<prod><cProd>PROD").append(i).append("</cProd>")
                    .append("<xProd>PRODUTO DE DEMONSTRACAO NUMERO ").append(i).append("</xProd>")
                    .append("<NCM>84713012</NCM><CFOP>5102</CFOP><uCom>UN</uCom>")
                    .append("<qCom>1.0000</qCom><vUnCom>150.0000000000</vUnCom><vProd>150.00</vProd></prod>")
                    .append("<imposto><ICMS><ICMS00><orig>0</orig><CST>00</CST>")
                    .append("<vBC>150.00</vBC><pICMS>18.00</pICMS><vICMS>27.00</vICMS></ICMS00></ICMS></imposto>")
                    .append("</det>");
        }
        sb.append("<total><ICMSTot><vBC>").append(detItems * 150).append(".00</vBC><vNF>")
                .append(detItems * 150).append(".00</vNF></ICMSTot></total>")
                .append("</infNFe></NFe>");
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }
}
