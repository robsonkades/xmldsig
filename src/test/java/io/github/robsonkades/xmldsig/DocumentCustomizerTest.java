package io.github.robsonkades.xmldsig;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilderFactory;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DocumentCustomizerTest {

    private static Document newDocument() throws Exception {
        return DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
    }

    @Test
    @DisplayName("andThen runs this customizer before the next one")
    void andThenRunsInOrder() throws Exception {
        List<String> order = new ArrayList<>();
        DocumentCustomizer first = document -> order.add("first");
        DocumentCustomizer second = document -> order.add("second");

        first.andThen(second).customize(newDocument());

        assertEquals(List.of("first", "second"), order);
    }

    @Test
    @DisplayName("andThen applies both mutations to the same document")
    void andThenAppliesBothMutations() throws Exception {
        Document document = newDocument();
        Element root = document.createElement("root");
        document.appendChild(root);

        DocumentCustomizer setA = doc -> doc.getDocumentElement().setAttribute("a", "1");
        DocumentCustomizer setB = doc -> doc.getDocumentElement().setAttribute("b", "2");

        setA.andThen(setB).customize(document);

        assertEquals("1", root.getAttribute("a"));
        assertEquals("2", root.getAttribute("b"));
    }

    @Test
    @DisplayName("andThen rejects a null next customizer")
    void andThenRejectsNull() {
        DocumentCustomizer customizer = document -> {
        };

        assertThrows(NullPointerException.class, () -> customizer.andThen(null));
    }
}
