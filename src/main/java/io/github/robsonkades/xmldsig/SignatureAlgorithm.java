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
 * Signature/digest algorithm pair used when signing.
 *
 * <p>{@link #RSA_SHA1} is the default, mandated by the SEFAZ signature schema
 * ({@code xmldsig-core-schema_v1.01.xsd}) for NF-e/NFC-e/CT-e/MDF-e and the national NFS-e model.
 * {@link #RSA_SHA256} exists for layouts that require it (some municipal NFS-e models); do not
 * select it where the layout fixes SHA-1 — the authorizer rejects the signature.
 *
 * <p>{@link XmlSigner#verifyIntegrity(byte[])} accepts both algorithms regardless of how the
 * signer was configured.
 *
 * @since 1.0
 */
public enum SignatureAlgorithm {

    /** RSA with SHA-1 digests: the SEFAZ-mandated default. */
    RSA_SHA1,

    /** RSA with SHA-256 digests, for layouts that mandate it. */
    RSA_SHA256
}
