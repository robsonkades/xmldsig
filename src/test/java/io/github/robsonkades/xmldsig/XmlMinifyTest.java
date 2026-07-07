package io.github.robsonkades.xmldsig;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XmlMinifyTest {

    private static Document parse(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        return factory.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    }

    private static boolean hasCommentChild(Node node) {
        for (Node child = node.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child.getNodeType() == Node.COMMENT_NODE) {
                return true;
            }
        }
        return false;
    }

    @Test
    @DisplayName("removes whitespace-only text nodes between elements")
    void removesStructuralWhitespace() throws Exception {
        Document document = parse("<root>\n  <a>x</a>\n  <b>y</b>\n</root>");

        XmlMinify.minify().customize(document);

        NodeList children = document.getDocumentElement().getChildNodes();
        assertEquals(2, children.getLength());
        assertEquals("a", children.item(0).getNodeName());
        assertEquals("b", children.item(1).getNodeName());
    }

    @Test
    @DisplayName("minify(true) removes XML comments")
    void removesComments() throws Exception {
        Document document = parse("<root><a>x</a><!-- drop me --></root>");

        XmlMinify.minify(true).customize(document);

        assertFalse(hasCommentChild(document.getDocumentElement()));
    }

    @Test
    @DisplayName("minify(false) preserves XML comments")
    void keepsCommentsWhenRequested() throws Exception {
        Document document = parse("<root><a>x</a><!-- keep me --></root>");

        XmlMinify.minify(false).customize(document);

        assertTrue(hasCommentChild(document.getDocumentElement()));
    }

    @Test
    @DisplayName("preserves meaningful leaf text content")
    void preservesLeafText() throws Exception {
        Document document = parse("<root>\n  <a>hello</a>\n</root>");

        XmlMinify.minify().customize(document);

        Element a = (Element) document.getElementsByTagName("a").item(0);
        assertEquals("hello", a.getTextContent());
    }
}
