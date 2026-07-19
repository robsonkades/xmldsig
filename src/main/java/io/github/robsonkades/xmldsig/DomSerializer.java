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
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

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
 * <p>Stateless and thread-safe. Output is buffered internally; a target stream receives large
 * writes only. {@link #writeToBytes(Document, int)} serializes straight into a growable array —
 * one full-document copy less than serializing into a {@code ByteArrayOutputStream}.
 */
final class DomSerializer {

    private static final byte[] CDATA_START = ascii("<![CDATA[");
    private static final byte[] CDATA_END = ascii("]]>");
    private static final byte[] AMP = ascii("&amp;");
    private static final byte[] LT = ascii("&lt;");
    private static final byte[] GT = ascii("&gt;");
    private static final byte[] QUOT = ascii("&quot;");
    private static final byte[] CR_REF = ascii("&#xD;");
    private static final byte[] TAB_REF = ascii("&#x9;");
    private static final byte[] LF_REF = ascii("&#xA;");

    private DomSerializer() {
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
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

    /**
     * Serializes into an exactly-sized {@code byte[]}. {@code sizeHint} should slightly exceed the
     * expected output size so the internal array never grows.
     */
    static byte[] writeToBytes(Document document, int sizeHint) throws IOException {
        Element root = document.getDocumentElement();
        if (root == null) {
            return new byte[0];
        }
        Buffer buffer = new Buffer(sizeHint);
        writeElement(root, buffer);
        return buffer.toByteArray();
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
                    out.put(CDATA_START);
                    writeRaw(child.getNodeValue(), out);
                    out.put(CDATA_END);
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
                case '&' -> out.put(AMP);
                case '<' -> out.put(LT);
                case '>' -> {
                    if (inAttribute) out.put((byte) '>');
                    else out.put(GT);
                }
                case '"' -> {
                    if (inAttribute) out.put(QUOT);
                    else out.put((byte) '"');
                }
                case '\r' -> out.put(CR_REF);
                case '\t' -> {
                    if (inAttribute) out.put(TAB_REF);
                    else out.put((byte) '\t');
                }
                case '\n' -> {
                    if (inAttribute) out.put(LF_REF);
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
     * {@code ByteArrayOutputStream}/{@code BufferedOutputStream}. Two modes: draining 8KB chunks
     * to an {@link OutputStream}, or growing in place for {@link #writeToBytes(Document, int)}.
     */
    private static final class Buffer {

        private final @Nullable OutputStream out;
        private byte[] data;
        private int position;

        Buffer(OutputStream out) {
            this.out = out;
            this.data = new byte[8192];
        }

        Buffer(int capacity) {
            this.out = null;
            this.data = new byte[Math.max(capacity, 64)];
        }

        void put(byte b) throws IOException {
            if (position == data.length) {
                makeRoom();
            }
            data[position++] = b;
        }

        void put(byte[] bytes) throws IOException {
            int offset = 0;
            while (offset < bytes.length) {
                if (position == data.length) {
                    makeRoom();
                }
                int chunk = Math.min(bytes.length - offset, data.length - position);
                System.arraycopy(bytes, offset, data, position, chunk);
                position += chunk;
                offset += chunk;
            }
        }

        private void makeRoom() throws IOException {
            if (out != null) {
                out.write(data, 0, position);
                position = 0;
            } else {
                data = Arrays.copyOf(data, data.length + (data.length >> 1));
            }
        }

        void finish() throws IOException {
            if (out != null) {
                out.write(data, 0, position);
                position = 0;
                out.flush();
            }
        }

        byte[] toByteArray() {
            return position == data.length ? data : Arrays.copyOf(data, position);
        }
    }
}
