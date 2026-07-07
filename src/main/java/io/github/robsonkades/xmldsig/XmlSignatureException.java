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

import java.io.Serial;

/**
 * Thrown for any XML signing, verification or customization failure.
 *
 * <p>Named {@code XmlSignatureException} (not {@code SignatureException}) to avoid
 * accidental import clashes with {@link java.security.SignatureException}.
 */
public final class XmlSignatureException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 4196064448805719012L;

    public XmlSignatureException(String message) {
        super(message);
    }

    public XmlSignatureException(String message, Throwable cause) {
        super(message, cause);
    }
}
