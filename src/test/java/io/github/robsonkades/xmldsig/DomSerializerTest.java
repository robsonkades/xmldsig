package io.github.robsonkades.xmldsig;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DomSerializerTest {

    private static Document parse(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        return factory.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    }

    private static String serialize(Document document) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        DomSerializer.write(document, out);
        return out.toString(StandardCharsets.UTF_8);
    }

    @Test
    @DisplayName("escapes & < > in text content")
    void escapesText() throws Exception {
        Document document = parse("<a>1 &amp; 2 &lt; 3 &gt; 4</a>");

        assertEquals("<a>1 &amp; 2 &lt; 3 &gt; 4</a>", serialize(document));
    }

    @Test
    @DisplayName("escapes & < and quotes in attribute values, keeping > literal")
    void escapesAttributes() throws Exception {
        Document document = parse("<a b=\"x &amp; y &lt; z &quot; w &gt; v\"/>");

        assertEquals("<a b=\"x &amp; y &lt; z &quot; w > v\"/>", serialize(document));
    }

    @Test
    @DisplayName("serializes an empty element as a self-closing tag")
    void selfClosesEmptyElement() throws Exception {
        Document document = parse("<a></a>");

        assertEquals("<a/>", serialize(document));
    }

    @Test
    @DisplayName("preserves CDATA sections verbatim")
    void preservesCdata() throws Exception {
        Document document = parse("<a><![CDATA[<raw> & </raw>]]></a>");

        assertEquals("<a><![CDATA[<raw> & </raw>]]></a>", serialize(document));
    }

    @Test
    @DisplayName("drops comments during serialization")
    void dropsComments() throws Exception {
        Document document = parse("<a>text<!-- comment --></a>");

        assertEquals("<a>text</a>", serialize(document));
    }

    @Test
    @DisplayName("serializes multibyte UTF-8 characters correctly")
    void serializesUtf8() throws Exception {
        Document document = parse("<a>ção €</a>");

        assertEquals("<a>ção €</a>", serialize(document));
    }

    @Test
    void streamAndGrowingArrayPreserveContentAcrossBufferBoundaries() throws Exception {
        for (int length : new int[]{63, 64, 8190, 8191, 8192, 16384}) {
            String content = "x".repeat(length) + "🚀ção\r\n\t<&>";
            Document document = parse("<a/>");
            document.getDocumentElement().setTextContent(content);
            document.getDocumentElement().setAttribute("value", "\r\n\t<&\"");
            byte[] stream = serialize(document).getBytes(StandardCharsets.UTF_8);
            byte[] array = DomSerializer.writeToBytes(document, 1);
            assertArrayEquals(stream, array, "length=" + length);
            Document reparsed = parse(new String(array, StandardCharsets.UTF_8));
            assertEquals(content, reparsed.getDocumentElement().getTextContent());
            assertEquals("\r\n\t<&\"", reparsed.getDocumentElement().getAttribute("value"));
        }
    }

    @Test
    void cdataDelimitersAndCarriageReturnsSurviveReparse() throws Exception {
        Document document = parse("<a/>");
        String value = "a]]>b\rc🚀";
        document.getDocumentElement().appendChild(document.createCDATASection(value));
        assertEquals(value, parse(serialize(document)).getDocumentElement().getTextContent());
    }

    @Test
    void rejectsUnpairedSurrogateInsteadOfWritingInvalidUtf8() throws Exception {
        Document document = parse("<a/>");
        document.getDocumentElement().setTextContent("\uD800");
        assertThrows(XmlSignatureException.class, () -> serialize(document));
    }
}
