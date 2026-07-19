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

import org.jspecify.annotations.Nullable;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;

/**
 * Immutable signing material: a private key plus its X.509 certificate chain.
 *
 * <p>Loading a credential from a {@link KeyStore} is expensive (PKCS#12 key decryption). Load it
 * <b>once</b> at startup and share the resulting {@code SigningCredential}/{@link XmlSigner} as a
 * singleton; never load per request. For multi-tenant deployments, cache one credential per
 * certificate, evicting before the certificate's {@code notAfter}.
 *
 * <p>The {@link #certificateChain()} list is immutable — callers cannot corrupt shared state.
 *
 * @param privateKey       the signing key (A1: software key; A3: PKCS#11 handle)
 * @param certificateChain the certificate chain, leaf first; never empty
 * @param alias            the keystore alias the material was loaded from (may be {@code null})
 */
public record SigningCredential(PrivateKey privateKey, List<X509Certificate> certificateChain, @Nullable String alias) {

    /**
     * Validates the components and defensively copies the certificate chain.
     *
     * @throws CredentialException if {@code certificateChain} is empty
     */
    public SigningCredential {
        Objects.requireNonNull(privateKey, "privateKey must not be null");
        Objects.requireNonNull(certificateChain, "certificateChain must not be null");
        certificateChain = List.copyOf(certificateChain);
        if (certificateChain.isEmpty()) {
            throw new CredentialException("certificateChain must contain at least the leaf certificate");
        }
    }

    /**
     * Returns the leaf (end-entity) certificate. Never {@code null}.
     *
     * @return the first certificate of {@link #certificateChain()}
     */
    public X509Certificate leafCertificate() {
        return certificateChain.getFirst();
    }

    /**
     * Best-effort detection of a hardware-backed key (A3 token/HSM via PKCS#11).
     *
     * <p>Software RSA keys (A1) expose CRT parameters; PKCS#11 handles do not. Hardware tokens
     * serialize signing operations — a smartcard performs ~10-20 signatures/second regardless of
     * concurrency. Under high load, route A3 signing through a dedicated bounded executor instead
     * of letting requests pile up on the PKCS#11 provider lock.
     *
     * @return {@code true} if the private key looks hardware-backed (no RSA CRT parameters)
     */
    public boolean isLikelyHardwareKey() {
        return !(privateKey instanceof RSAPrivateCrtKey);
    }

    /**
     * Creates a credential from the first private-key entry in the keystore.
     *
     * <p>The caller owns {@code keyPassword} and should zero it after use. Prefer this overload
     * over String-based passwords: a password that ever lived in a {@code String} cannot be
     * scrubbed from the heap.
     *
     * @param keyStore    the loaded keystore to read from; must not be {@code null}
     * @param keyPassword the password protecting the private-key entry
     * @return the credential for the first private-key entry
     */
    public static SigningCredential fromKeyStore(KeyStore keyStore, char[] keyPassword) {
        return fromKeyStore(keyStore, keyPassword, null);
    }

    /**
     * Creates a credential from the given keystore alias (or the first key entry when
     * {@code alias} is {@code null} or blank).
     *
     * @param keyStore    the loaded keystore to read from; must not be {@code null}
     * @param keyPassword the password protecting the private-key entry
     * @param alias       the entry to load, or {@code null}/blank for the first key entry
     * @return the credential for the resolved alias
     */
    public static SigningCredential fromKeyStore(KeyStore keyStore, char[] keyPassword, @Nullable String alias) {
        if (keyStore == null) {
            throw new CredentialException("KeyStore must not be null");
        }
        try {
            String resolvedAlias = resolveAlias(keyStore, alias);
            Key key = keyStore.getKey(resolvedAlias, keyPassword);
            if (!(key instanceof PrivateKey privateKey)) {
                throw new CredentialException("No private key found for alias '" + resolvedAlias + "'");
            }
            List<X509Certificate> chain = certificateChainForAlias(keyStore, resolvedAlias);
            if (chain.isEmpty()) {
                throw new CredentialException("No X509 certificate found for alias '" + resolvedAlias + "'");
            }
            return new SigningCredential(privateKey, chain, resolvedAlias);
        } catch (GeneralSecurityException ex) {
            throw new CredentialException("Unable to load XML signing material", ex);
        }
    }

    private static String resolveAlias(KeyStore keyStore, @Nullable String alias) throws KeyStoreException {
        if (alias != null && !alias.isBlank()) {
            if (!keyStore.containsAlias(alias)) {
                throw new CredentialException("Keystore does not contain alias '" + alias + "'");
            }
            return alias;
        }
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String candidate = aliases.nextElement();
            if (keyStore.isKeyEntry(candidate)) {
                return candidate;
            }
        }
        throw new CredentialException("No key entries found in keystore");
    }

    private static List<X509Certificate> certificateChainForAlias(KeyStore keyStore, String alias) throws KeyStoreException {
        Certificate[] chain = keyStore.getCertificateChain(alias);
        if (chain == null || chain.length == 0) {
            Certificate single = keyStore.getCertificate(alias);
            return (single instanceof X509Certificate x509) ? List.of(x509) : List.of();
        }
        List<X509Certificate> certificates = new ArrayList<>(chain.length);
        for (Certificate certificate : chain) {
            if (certificate instanceof X509Certificate x509) {
                certificates.add(x509);
            }
        }
        return List.copyOf(certificates);
    }
}
