import java.io.Reader;
import java.io.StringReader;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

public class XMLHelper {
	public static Document retrieveXml(String doc) {
		try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			DocumentBuilder documentBuilder = dbf.newDocumentBuilder();
			Reader reader = new StringReader(doc);
			InputSource is = new InputSource(reader);
			is.setEncoding("ISO-8859-15");
			Document document = documentBuilder.parse(is);
			return document;
		}

		catch (Exception e) {
			throw new IllegalStateException("Das DOM-Modell konnte nicht aus dem übergebenen String erzeugt werden.",
					e);
		}

	}

	public static Document cloneDocument(Document doc) {
		try {
			TransformerFactory tfactory = TransformerFactory.newInstance();
			Transformer transformer = tfactory.newTransformer();
			/*transformer.setOutputProperty(OutputKeys.ENCODING, ConfigHolder.Encoding.getConfigured());*/
			DOMSource source = new DOMSource(doc);
			DOMResult result = new DOMResult();
			transformer.transform(source, result);
			Document clone = (Document) result.getNode();

			
			return clone;
		} catch (Exception e) {
			throw new IllegalStateException("Klonen des DOM-Modells ist fehlgeschlagen", e);
		}

	}

	public static Element findIdenticalElementInDocument(Element findCopyOfElement, Document inThisDocument) {
		if (inThisDocument.getDocumentElement().getTagName().equals(findCopyOfElement.getTagName())) {
			if (inThisDocument.getDocumentElement().isEqualNode(findCopyOfElement)) {
				return inThisDocument.getDocumentElement();
			}

		}
		NodeList nodes = inThisDocument.getElementsByTagName(findCopyOfElement.getTagName());
		for (int x = 0; x < nodes.getLength(); x++) {
			Node node = nodes.item(0);
			System.out.println(node.getNodeName());
			if (node.isEqualNode(findCopyOfElement)) {
				return (Element) node;
			}

		}
		return null;
	}
}
