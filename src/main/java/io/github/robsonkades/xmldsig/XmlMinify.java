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

import javax.xml.XMLConstants;

/**
 * Factory for {@link DocumentCustomizer}s that shrink a document before signing.
 *
 * <p>Removes line-breaking formatting whitespace between elements and, optionally, XML comments.
 * Whitespace is part of canonical XML: use this only before signing and only for layouts in which
 * indentation is insignificant. Inline spaces, mixed text and inherited {@code xml:space="preserve"}
 * are retained. Compose via {@link DocumentCustomizer#andThen(DocumentCustomizer)}.
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
     * Removes whitespace-only nodes containing a line break in element-only content and, optionally,
     * comments. Respects {@code xml:space}; without a schema, indentation remains a layout assumption.
     *
     * @param removeComments whether to remove XML comments
     * @return a customizer that removes structural whitespace (and comments when requested)
     */
    public static DocumentCustomizer minify(boolean removeComments) {
        return document -> {
            Element root = document.getDocumentElement();
            if (root != null) {
                cleanSubtree(root, removeComments, false);
            }
        };
    }

    private static void cleanSubtree(Element node, boolean removeComments, boolean inheritedPreserve) {
        String space = node.getAttributeNS(XMLConstants.XML_NS_URI, "space");
        if (space.isEmpty()) {
            // A preceding customizer may have used DOM Level 1 setAttribute before normalization.
            space = node.getAttribute("xml:space");
        }
        boolean preserve = "preserve".equals(space) || (inheritedPreserve && !"default".equals(space));
        // Computed once per parent instead of once per text node (was O(n^2)).
        boolean hasElementChild = false;
        boolean hasTextContent = false;
        for (Node child = node.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child.getNodeType() == Node.ELEMENT_NODE) {
                hasElementChild = true;
            } else if ((child.getNodeType() == Node.TEXT_NODE && !isWhitespaceOnly(child.getNodeValue()))
                    || child.getNodeType() == Node.CDATA_SECTION_NODE) {
                hasTextContent = true;
            }
        }
        Node child = node.getFirstChild();
        while (child != null) {
            Node next = child.getNextSibling();
            switch (child.getNodeType()) {
                case Node.ELEMENT_NODE -> cleanSubtree((Element) child, removeComments, preserve);
                case Node.TEXT_NODE -> {
                    String value = ((Text) child).getData();
                    if (!preserve && !hasTextContent && hasElementChild && isWhitespaceOnly(value)
                            && (value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0)) {
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
            char c = s.charAt(i);
            if (c != ' ' && c != '\t' && c != '\r' && c != '\n') {
                return false;
            }
        }
        return true;
    }
}
