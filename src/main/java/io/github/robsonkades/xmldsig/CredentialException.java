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
 * Thrown when signing material cannot be loaded — for example a missing keystore alias, a wrong
 * key password, or a keystore entry without a private key or X.509 certificate chain.
 */
public final class CredentialException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 3746923476829840508L;

    /**
     * Creates the exception with a detail message.
     *
     * @param message the detail message
     */
    public CredentialException(String message) {
        super(message);
    }

    /**
     * Creates the exception with a detail message and the underlying cause.
     *
     * @param message the detail message
     * @param cause   the underlying failure
     */
    public CredentialException(String message, Throwable cause) {
        super(message, cause);
    }
}
