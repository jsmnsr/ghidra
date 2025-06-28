package ghidra.features.bsim.query;

import static org.junit.Assert.*;

import java.io.File;
import java.nio.file.Files;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.junit.Test;
import org.w3c.dom.Document;
import generic.test.AbstractGTest;

/**
 * Tests demonstrating the XXE vulnerability in {@link FunctionDatabase#isConfigTemplate}
 * and verifying it is now mitigated.
 */
public class FunctionDatabaseSecurityTest extends AbstractGTest {

    @Test
    public void testIsConfigTemplateRejectsExternalEntity() throws Exception {
        File dir = new File(getTestDirectoryPath());
        File secret = new File(dir, "secret.txt");
        Files.write(secret.toPath(), "SECRET".getBytes());

        String xml = "<!DOCTYPE dbconfig [<!ENTITY xxe SYSTEM '" + secret.toURI().toString() + "'>]>" +
                      "<dbconfig>&xxe;</dbconfig>";
        File xmlFile = new File(dir, "malicious.xml");
        Files.write(xmlFile.toPath(), xml.getBytes());

        // Simulate old vulnerable parser
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(xmlFile);
        assertEquals("SECRET", doc.getDocumentElement().getTextContent().trim());

        // Current implementation should not resolve external entities
        boolean result = FunctionDatabase.isConfigTemplate(xmlFile);
        assertFalse(result);
    }
}
