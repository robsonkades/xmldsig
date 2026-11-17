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

    @Test
    void preservesInlineSeparatorsAndMixedContent() throws Exception {
        for (String xml : new String[]{"<root><a>one</a> <b>two</b></root>",
                "<root>before\n<a>one</a>\n after</root>"}) {
            Document document = parse(xml);
            String before = document.getDocumentElement().getTextContent();
            XmlMinify.minify().customize(document);
            assertEquals(before, document.getDocumentElement().getTextContent());
        }
    }

    @Test
    void respectsInheritedXmlSpaceAndExplicitDefault() throws Exception {
        Document document = parse("<root xml:space=\"preserve\">\n<a>\n<b/>\n</a>"
                + "<c xml:space=\"default\">\n<d/>\n</c>\n</root>");
        XmlMinify.minify().customize(document);
        assertEquals("\n\n", document.getElementsByTagName("a").item(0).getTextContent());
        assertEquals("", document.getElementsByTagName("c").item(0).getTextContent());
        assertEquals(Node.TEXT_NODE, document.getDocumentElement().getFirstChild().getNodeType());
    }

    @Test
    void leavesCdataAndWhitespaceLeavesUntouched() throws Exception {
        Document document = parse("<root><![CDATA[ ]]><a> \n </a>\n<b/></root>");
        String before = document.getDocumentElement().getTextContent();
        XmlMinify.minify().customize(document);
        assertEquals(before, document.getDocumentElement().getTextContent());
    }

    @Test
    void preservesXmlSpaceSetByAnEarlierCustomizerUsingDomLevelOne() throws Exception {
        Document document = parse("<root>\n<a/>\n</root>");
        DocumentCustomizer preserve = doc -> doc.getDocumentElement().setAttribute("xml:space", "preserve");
        preserve.andThen(XmlMinify.minify()).customize(document);
        assertEquals("\n\n", document.getDocumentElement().getTextContent());
    }
}
