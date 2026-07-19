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

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

/**
 * Factory for {@link DocumentCustomizer}s that shrink a document before signing.
 *
 * <p>Removes whitespace-only text nodes between elements and, optionally, XML comments — both are
 * excluded from inclusive C14N, so minifying never changes signature validity. Compose with other
 * customizers via {@link DocumentCustomizer#andThen(DocumentCustomizer)}.
 */
public final class XmlMinify {

    private XmlMinify() {
        // empty constructor
    }

    /**
     * Removes structural whitespace and comments. Equivalent to {@code minify(true)}.
     *
     * @return a customizer that removes structural whitespace and comments
     */
    public static DocumentCustomizer minify() {
        return minify(true);
    }

    /**
     * Removes structural whitespace (whitespace-only text nodes with element siblings) and,
     * optionally, comments.
     *
     * @param removeComments whether to remove XML comments
     * @return a customizer that removes structural whitespace (and comments when requested)
     */
    public static DocumentCustomizer minify(boolean removeComments) {
        return document -> {
            Element root = document.getDocumentElement();
            if (root != null) {
                cleanSubtree(root, removeComments);
            }
        };
    }

    private static void cleanSubtree(Node node, boolean removeComments) {
        // Computed once per parent instead of once per text node (was O(n^2)).
        boolean hasElementChild = false;
        for (Node child = node.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child.getNodeType() == Node.ELEMENT_NODE) {
                hasElementChild = true;
                break;
            }
        }
        Node child = node.getFirstChild();
        while (child != null) {
            Node next = child.getNextSibling();
            switch (child.getNodeType()) {
                case Node.ELEMENT_NODE -> cleanSubtree(child, removeComments);
                case Node.TEXT_NODE -> {
                    if (hasElementChild && isWhitespaceOnly(((Text) child).getData())) {
                        node.removeChild(child);
                    }
                }
                case Node.COMMENT_NODE -> {
                    if (removeComments) {
                        node.removeChild(child);
                    }
                }
                default -> {
                    // keep everything else
                }
            }
            child = next;
        }
    }

    private static boolean isWhitespaceOnly(String s) {
        if (s == null || s.isEmpty()) {
            return true;
        }
        for (int i = 0, length = s.length(); i < length; i++) {
            if (s.charAt(i) > ' ') { // anything above ' ' is not XML whitespace (space, tab, cr, lf)
                return false;
            }
        }
        return true;
    }
}
