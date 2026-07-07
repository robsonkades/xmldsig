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
 */
@NullMarked
package io.github.robsonkades.xmldsig;

import org.jspecify.annotations.NullMarked;
