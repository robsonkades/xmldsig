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

package io.github.robsonkades.xmldsig;

/**
 * Outcome of an XML signature integrity check.
 *
 * <p>See {@link XmlSigner#verifyIntegrity(byte[])} for the exact semantics — in particular,
 * a valid result does <b>not</b> establish trust in the signer's certificate.
 *
 * @param valid  whether the signature is structurally acceptable and cryptographically consistent
 * @param detail human-readable reason when invalid; {@code "OK"} when valid
 */
public record VerificationResult(boolean valid, String detail) {

    private static final VerificationResult OK = new VerificationResult(true, "OK");

    static VerificationResult ok() {
        return OK;
    }

    static VerificationResult invalid(String detail) {
        return new VerificationResult(false, detail);
    }
}
