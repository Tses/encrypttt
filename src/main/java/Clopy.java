import org.apache.xml.security.Init;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.utils.EncryptionConstants;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.security.*;

/**
 * 
 * author: Pascal Knueppel created at: 08.05.2015
 */
public class Clopy {

	private PublicKey publicKey;
	private PrivateKey privateKey;
	private SecretKey secretKey;

	public Clopy(PublicKey publicKey, PrivateKey privateKey) {
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}

	private SecretKey generateSecretKey() throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(128);
		SecretKey secretKey = keyGenerator.generateKey();
		SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");
		return secretKeySpec;
	}

	public Document encryptElement_withPublicKey(Element encryptionElement, boolean encryptContent) throws Exception {
		Document document = XMLHelper.cloneDocument(encryptionElement.getOwnerDocument());
		encryptionElement = XMLHelper.findIdenticalElementInDocument(encryptionElement, document);
		SecretKey dataKey = generateSecretKey();
		this.setSecretKey(dataKey);
		assert !secretKey.getAlgorithm().equals("RSA");
		XMLCipher keyCipher = XMLCipher.getInstance(XMLCipher.RSA_OAEP);
		keyCipher.init(XMLCipher.WRAP_MODE, publicKey);
		XMLCipher xmlCipher = XMLCipher.getInstance(XMLCipher.AES_256);
		EncryptedKey encryptedKey = keyCipher.encryptKey(document, dataKey);
		xmlCipher.init(XMLCipher.ENCRYPT_MODE, dataKey);
		EncryptedData encryptedData = xmlCipher.getEncryptedData();
		KeyInfo keyInfo = new KeyInfo(document);
		keyInfo.add(encryptedKey);
		keyInfo.addKeyName("rsaKeyName");
		encryptedData.setKeyInfo(keyInfo);
		xmlCipher.doFinal(document, encryptionElement, encryptContent);
		return document;
	}

	public Document decryptDocument_withPrivateKey(Document document) throws Exception {
		Document encryptedDocument = XMLHelper.cloneDocument(document);
		Element encryptedDataElement = (Element) encryptedDocument
				.getElementsByTagNameNS(EncryptionConstants.EncryptionSpecNS, EncryptionConstants._TAG_ENCRYPTEDDATA)
				.item(0);
		XMLCipher xmlCipher = XMLCipher.getInstance();
		xmlCipher.init(XMLCipher.DECRYPT_MODE, null);
		EncryptedData encryptedData = xmlCipher.loadEncryptedData(document, encryptedDataElement);
		EncryptedKey encryptedKey = xmlCipher.loadEncryptedKey(document, encryptedData.getKeyInfo().getElement());
		xmlCipher.init(XMLCipher.UNWRAP_MODE, privateKey);
		secretKey = (SecretKey) xmlCipher.decryptKey(encryptedKey, encryptedKey.getEncryptionMethod().getAlgorithm());
		secretKey = (SecretKey) xmlCipher.decryptKey(encryptedKey, encryptedData.getEncryptionMethod().getAlgorithm());
		setSecretKey(secretKey);
		xmlCipher.init(XMLCipher.DECRYPT_MODE, null);
		xmlCipher.setKEK(privateKey);
		xmlCipher.doFinal(encryptedDocument, encryptedDataElement);
		return encryptedDocument;
	}

	public void setSecretKey(SecretKey secretKey) {
		assert !secretKey.getAlgorithm().equals("RSA");
		this.secretKey = secretKey;
	}

	public static KeyPair generateKey(String algorithm, KeyGenerationParameters keyGenerationParameters)
			throws NoSuchAlgorithmException, NoSuchProviderException {
		KeyPairGenerator keyPairGenerator = null;
		keyPairGenerator = KeyPairGenerator.getInstance(algorithm, "BC");
		keyPairGenerator.initialize(keyGenerationParameters.getStrength(), keyGenerationParameters.getRandom());
		return keyPairGenerator.generateKeyPair();
	}

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

	public static void main(String[] args) throws Exception {
		Init.init();
		Security.addProvider(new BouncyCastleProvider());
		KeyPair myKeys = generateKey("RSA", new KeyGenerationParameters(new SecureRandom(), 2048));
		Clopy myXmlCrypto = new Clopy(myKeys.getPublic(), myKeys.getPrivate());
		Document document = retrieveXml("<Request><data></data></Request>");
		Document encrypted = myXmlCrypto.encryptElement_withPublicKey(document.getDocumentElement(), true);
		Document decrypted = myXmlCrypto.decryptDocument_withPrivateKey(encrypted);
	}

}