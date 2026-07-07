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

import org.w3c.dom.*;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Minimal, allocation-light DOM to UTF-8 serializer for fiscal XML.
 *
 * <p>Replaces the per-call {@code TransformerFactory.newTransformer()} pipeline. Output rules:
 * <ul>
 *   <li>No XML declaration, no indentation (SEFAZ layout).</li>
 *   <li>C14N-compatible escaping: {@code & < >} (and {@code CR}) in text; {@code & < "} and
 *       whitespace character references in attribute values. A serialized document therefore
 *       re-parses to a DOM whose canonicalization is byte-identical — signed content is never
 *       corrupted by serialization.</li>
 *   <li>CDATA sections are preserved verbatim (SEFAZ convention for {@code qrCodCTe}).</li>
 *   <li>Comments and processing instructions are dropped (excluded from inclusive C14N anyway,
 *       so this never affects signature validity).</li>
 * </ul>
 *
 * <p>Stateless and thread-safe. Output is buffered internally; the target stream receives
 * large writes only.
 */
final class DomSerializer {

    private DomSerializer() {
    }

    static void write(Document document, OutputStream out) throws IOException {
        Element root = document.getDocumentElement();
        if (root == null) {
            return;
        }
        Buffer buffer = new Buffer(out);
        writeElement(root, buffer);
        buffer.finish();
    }

    private static void writeElement(Element element, Buffer out) throws IOException {
        out.put((byte) '<');
        writeRaw(element.getNodeName(), out);
        NamedNodeMap attributes = element.getAttributes();
        for (int i = 0, n = attributes.getLength(); i < n; i++) {
            Attr attribute = (Attr) attributes.item(i);
            out.put((byte) ' ');
            writeRaw(attribute.getName(), out);
            out.put((byte) '=');
            out.put((byte) '"');
            writeEscaped(attribute.getValue(), true, out);
            out.put((byte) '"');
        }
        Node child = element.getFirstChild();
        if (child == null) {
            out.put((byte) '/');
            out.put((byte) '>');
            return;
        }
        out.put((byte) '>');
        for (; child != null; child = child.getNextSibling()) {
            switch (child.getNodeType()) {
                case Node.ELEMENT_NODE -> writeElement((Element) child, out);
                case Node.TEXT_NODE -> writeEscaped(child.getNodeValue(), false, out);
                case Node.CDATA_SECTION_NODE -> {
                    out.putAscii("<![CDATA[");
                    writeRaw(child.getNodeValue(), out);
                    out.putAscii("]]>");
                }
                default -> {
                    // comments/PIs intentionally dropped; entity refs cannot occur (DTDs disallowed)
                }
            }
        }
        out.put((byte) '<');
        out.put((byte) '/');
        writeRaw(element.getNodeName(), out);
        out.put((byte) '>');
    }

    private static void writeEscaped(String value, boolean inAttribute, Buffer out) throws IOException {
        for (int i = 0, n = value.length(); i < n; i++) {
            char c = value.charAt(i);
            switch (c) {
                case '&' -> out.putAscii("&amp;");
                case '<' -> out.putAscii("&lt;");
                case '>' -> {
                    if (inAttribute) out.put((byte) '>');
                    else out.putAscii("&gt;");
                }
                case '"' -> {
                    if (inAttribute) out.putAscii("&quot;");
                    else out.put((byte) '"');
                }
                case '\r' -> out.putAscii("&#xD;");
                case '\t' -> {
                    if (inAttribute) out.putAscii("&#x9;");
                    else out.put((byte) '\t');
                }
                case '\n' -> {
                    if (inAttribute) out.putAscii("&#xA;");
                    else out.put((byte) '\n');
                }
                default -> i = putChar(value, i, c, out);
            }
        }
    }

    private static void writeRaw(String value, Buffer out) throws IOException {
        for (int i = 0, n = value.length(); i < n; i++) {
            i = putChar(value, i, value.charAt(i), out);
        }
    }

    /**
     * Writes one character (or surrogate pair) as UTF-8. Returns the possibly advanced index.
     */
    private static int putChar(String value, int i, char c, Buffer out) throws IOException {
        if (c < 0x80) {
            out.put((byte) c);
            return i;
        }
        int codePoint = c;
        if (Character.isHighSurrogate(c) && i + 1 < value.length()
                && Character.isLowSurrogate(value.charAt(i + 1))) {
            codePoint = Character.toCodePoint(c, value.charAt(i + 1));
            i++;
        }
        if (codePoint < 0x800) {
            out.put((byte) (0xC0 | (codePoint >> 6)));
            out.put((byte) (0x80 | (codePoint & 0x3F)));
        } else if (codePoint < 0x10000) {
            out.put((byte) (0xE0 | (codePoint >> 12)));
            out.put((byte) (0x80 | ((codePoint >> 6) & 0x3F)));
            out.put((byte) (0x80 | (codePoint & 0x3F)));
        } else {
            out.put((byte) (0xF0 | (codePoint >> 18)));
            out.put((byte) (0x80 | ((codePoint >> 12) & 0x3F)));
            out.put((byte) (0x80 | ((codePoint >> 6) & 0x3F)));
            out.put((byte) (0x80 | (codePoint & 0x3F)));
        }
        return i;
    }

    /**
     * Small internal write buffer: avoids the per-byte monitor of
     * {@code ByteArrayOutputStream}/{@code BufferedOutputStream}.
     */
    private static final class Buffer {

        private final byte[] data = new byte[8192];
        private final OutputStream out;
        private int position;

        Buffer(OutputStream out) {
            this.out = out;
        }

        void put(byte b) throws IOException {
            if (position == data.length) {
                drain();
            }
            data[position++] = b;
        }

        void putAscii(String s) throws IOException {
            for (int i = 0, n = s.length(); i < n; i++) {
                put((byte) s.charAt(i));
            }
        }

        private void drain() throws IOException {
            out.write(data, 0, position);
            position = 0;
        }

        void finish() throws IOException {
            drain();
            out.flush();
        }
    }
}
