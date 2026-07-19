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

import org.w3c.dom.Document;

import java.util.Objects;

/**
 * Mutates a parsed XML {@link Document} before it is signed.
 *
 * <p>Customizers compose: {@code first.andThen(second)} runs both over the same DOM within a single
 * parse/sign/serialize cycle. Re-parsing between customization steps is the most common performance
 * mistake when using this library — always compose customizers instead of chaining separate
 * sign/serialize calls.
 *
 * @see XmlSigner#sign(byte[], DocumentCustomizer)
 */
@FunctionalInterface
public interface DocumentCustomizer {

    /**
     * Applies this customization to the given document in place.
     *
     * @param document the document to mutate; never {@code null}
     */
    void customize(Document document);

    /**
     * Returns a composed customizer that applies this customizer first, then {@code next}.
     *
     * @param next the customizer to apply after this one
     * @return the composed customizer
     */
    default DocumentCustomizer andThen(DocumentCustomizer next) {
        Objects.requireNonNull(next, "next must not be null");
        return document -> {
            customize(document);
            next.customize(document);
        };
    }
}
