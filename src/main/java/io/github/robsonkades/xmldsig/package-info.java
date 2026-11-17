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

/**
 * High-performance XML Digital Signature for Brazilian fiscal documents (NF-e, NFC-e, CT-e, MDF-e).
 *
 * <p>Entry points:
 * <ul>
 *   <li>{@link io.github.robsonkades.xmldsig.SigningCredential} — loads the private key and
 *       certificate chain from a {@link java.security.KeyStore}.</li>
 *   <li>{@link io.github.robsonkades.xmldsig.XmlSigner} — signs and verifies; create one per
 *       certificate at startup and share it.</li>
 *   <li>{@link io.github.robsonkades.xmldsig.DocumentCustomizer} — optional in-place DOM mutation
 *       before signing (see {@link io.github.robsonkades.xmldsig.XmlMinify}).</li>
 * </ul>
 *
 * <p>See {@link io.github.robsonkades.xmldsig.XmlSigner} for algorithm and initialization details.
 *
 * <p><b>Anti-patterns.</b> Each of these has broken fiscal signatures or throughput in production:
 * <ul>
 *   <li><b>Pretty-printing a signed document</b> (a {@code Transformer} with {@code INDENT=yes},
 *       an IDE formatter, a "beautifier" gateway): whitespace added inside the signed element
 *       changes its digest and the authorizer rejects the signature. Serialize only through the
 *       signing pipeline, and transmit the bytes it produced.</li>
 *   <li><b>Editing signed XML as text</b> ({@code String.replaceAll}, regex, concatenation) —
 *       same reason. Shrink or adjust the document <em>before</em> signing, in the same DOM pass
 *       ({@link io.github.robsonkades.xmldsig.XmlMinify},
 *       {@link io.github.robsonkades.xmldsig.DocumentCustomizer}).</li>
 *   <li><b>Customize–serialize–reparse–sign chains</b>: every extra parse costs a full DOM build.
 *       Compose customizers and use
 *       {@link io.github.robsonkades.xmldsig.XmlSigner#sign(byte[],
 *       io.github.robsonkades.xmldsig.DocumentCustomizer)} — one parse per document.</li>
 *   <li><b>Reloading the PFX/keystore per request</b>: PKCS#12 key decryption costs milliseconds
 *       and dominates small-document signing. Load once into
 *       {@link io.github.robsonkades.xmldsig.SigningCredential} and share the signer; in
 *       multi-tenant services cache one signer per certificate, evicting before the
 *       certificate's {@code notAfter}.</li>
 *   <li><b>Re-signing an already signed document</b>: would append a second {@code Signature}
 *       element, which every authorizer rejects — {@code sign} fails fast on it. Re-emission
 *       flows should drop the old signature in a
 *       {@link io.github.robsonkades.xmldsig.DocumentCustomizer} (runs before the check).</li>
 *   <li><b>Sharing non-thread-safe XML/crypto objects</b> ({@code DocumentBuilder},
 *       {@code Transformer}, {@code SignatureMethod}, {@code java.security.Signature}) across
 *       threads: intermittent corruption under load. The library already shares exactly what is
 *       safe to share; do not cache its building blocks yourself.</li>
 *   <li><b>Converting byte input to String just to sign it</b>: prefer the {@code byte[]}/stream
 *       overloads when the input is already encoded. String input is parsed as characters.</li>
 *   <li><b>Virtual threads for the signing step</b>: signing is CPU-bound (dominated by the RSA
 *       private-key operation), so virtual threads add nothing — size a fixed platform-thread
 *       pool to the core count. Keep virtual threads for the I/O around it (transmission to
 *       SEFAZ, storage).</li>
 * </ul>
 */
@NullMarked
package io.github.robsonkades.xmldsig;

import org.jspecify.annotations.NullMarked;
