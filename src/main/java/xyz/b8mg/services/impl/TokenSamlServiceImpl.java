package xyz.b8mg.services.impl;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Properties;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLException;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.Namespace;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.KeyName;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import xyz.b8mg.bean.TokenBean;
import xyz.b8mg.services.TokenSamlService;
import xyz.b8mg.util.constants;

public class TokenSamlServiceImpl implements TokenSamlService {

	@Override
	public TokenBean createTokenSaml(String input_audiencie, String input_issuer, boolean fail) throws Exception {
		int assertionTtlSeconds = constants.TIME_EXPIRATION_TOKEN_SAML;
		String emisorTokenSaml = constants.ISSUER_TOKEN_SAML; 

		dumpParserDetails();
		DefaultBootstrap.bootstrap();

		Assertion assertion = (Assertion) createSamlObject(Assertion.DEFAULT_ELEMENT_NAME);
		Namespace dsns = new Namespace("http://www.w3.org/2000/09/xmldsig#", "ds");
		assertion.addNamespace(dsns);
		Namespace xsins = new Namespace("http://www.w3.org/2001/XMLSchema-instance", "xsi");
		assertion.addNamespace(xsins);
		assertion.setVersion(SAMLVersion.VERSION_20);
		assertion.setID("123"); // in reality, must be unique for all assertions
		assertion.setIssueInstant(new DateTime());

		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

		SAMLObjectBuilder<Conditions> conditionsBuilder = (SAMLObjectBuilder<Conditions>) builderFactory.getBuilder(Conditions.DEFAULT_ELEMENT_NAME);
		Conditions conditions = conditionsBuilder.buildObject();
		conditions.setNotBefore(new DateTime());
		conditions.setNotOnOrAfter(new DateTime().plusSeconds(assertionTtlSeconds));

		Issuer issuer = (Issuer) createSamlObject(Issuer.DEFAULT_ELEMENT_NAME); 
		issuer.setValue(constants.ISSUER_TOKEN_SAML);
		assertion.setIssuer(issuer);

		Subject subj = (Subject) createSamlObject(Subject.DEFAULT_ELEMENT_NAME);
		assertion.setSubject(subj);

		NameID nameId = (NameID) createSamlObject(NameID.DEFAULT_ELEMENT_NAME);
		nameId.setValue(input_issuer);
		subj.setNameID(nameId);

		Audience audience = (Audience) createSamlObject(Audience.DEFAULT_ELEMENT_NAME);
		audience.setAudienceURI(input_audiencie);

		AudienceRestriction audienceRestriction = (AudienceRestriction) createSamlObject(AudienceRestriction.DEFAULT_ELEMENT_NAME);
		audienceRestriction.getAudiences().add(audience);

		conditions.getAudienceRestrictions().add(audienceRestriction); 

		assertion.setConditions(conditions);

		SubjectConfirmation subjConf = (SubjectConfirmation) createSamlObject(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
		subjConf.setMethod("urn:oasis:names:tc:2.0:cm:holder-of-key");
		subj.getSubjectConfirmations().add(subjConf);

		SubjectConfirmationData subjData = (SubjectConfirmationData) createSamlObject(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
		subjData.getUnknownAttributes().put(new QName("http://www.w3.org/2001/XMLSchema-instance", "type", "xsi"),
		   "saml:KeyInfoConfirmationDataType");
		subjConf.setSubjectConfirmationData(subjData);

		KeyInfo ki = (KeyInfo) createSamlObject(KeyInfo.DEFAULT_ELEMENT_NAME);
		subjData.getUnknownXMLObjects().add(ki);

		KeyName kn = (KeyName) createSamlObject(KeyName.DEFAULT_ELEMENT_NAME);
		kn.setValue("myclientkey");
		ki.getKeyNames().add(kn);        

		AttributeStatement as = (AttributeStatement) createSamlObject(AttributeStatement.DEFAULT_ELEMENT_NAME);
		assertion.getAttributeStatements().add(as);

		/*
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		char[] password = "cspass".toCharArray();
		FileInputStream fis = new FileInputStream("D:/directorio/certificado/clientKeystore.jks");
		ks.load(fis, password);
		fis.close();

		KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
		        ks.getEntry("myclientkey", new KeyStore.PasswordProtection("ckpass".toCharArray()));
		PrivateKey pk = pkEntry.getPrivateKey();
		X509Certificate certificate = (X509Certificate) pkEntry.getCertificate();

		BasicX509Credential credential = new BasicX509Credential();
		credential.setEntityCertificate(certificate);
		credential.setPrivateKey(pk);
		Signature signature = (Signature) createSamlObject(Signature.DEFAULT_ELEMENT_NAME);

		signature.setSigningCredential(credential);
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

		KeyInfo keyinfo = (KeyInfo) createSamlObject(KeyInfo.DEFAULT_ELEMENT_NAME);
		signature.setKeyInfo(keyinfo);

		assertion.setSignature(signature);
		*/

		//marshall Assertion Java class into XML
		MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
		Marshaller marshaller = marshallerFactory.getMarshaller(assertion);
		Element assertionElement = marshaller.marshall(assertion);
		
		/*
		try {
		    Signer.signObject(signature);
		} catch (SignatureException e) {
		    e.printStackTrace();
		}*/
		
		
		String xml= nodeToString(assertionElement, fail);
	    TokenBean tokenBean = new TokenBean();
	    tokenBean.setVersion(assertion.getVersion().toString());
		tokenBean.setContent(xml);
		tokenBean.setTimeExpiration(constants.TIME_EXPIRATION_TOKEN_SAML+"");	
		System.out.println(xml);
		return tokenBean;
	}

	private XMLObject createSamlObject(QName qname) {
	    return Configuration.getBuilderFactory().getBuilder(qname).buildObject(qname);
	}
	
	private String nodeToString(Node node, boolean indent) throws Exception {
	    StringWriter sw = new StringWriter();
	    TransformerFactory tfactory = createTransformerFactory();
	    Transformer transformer = tfactory.newTransformer();
	    if (indent) {
	        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
	        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
	    }
	    transformer.transform(new DOMSource(node), new StreamResult(sw));
	    sw.close();
	    return sw.toString();
	}

	private TransformerFactory createTransformerFactory() {
	    TransformerFactory tfactory = TransformerFactory.newInstance();
	    return tfactory;
	}
	
	private static void dumpParserDetails() {
	    {
	        DocumentBuilder builder = null;
	        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	        try {
	            builder = factory.newDocumentBuilder();
	            System.out.print("\nDocumentBuilderFactory Instance: " +factory.getClass().getName() +
	                         "\nDocumentBuilder Instance: " +builder.getClass().getName() + "\n");
	        }
	        catch (Exception e) {
	            System.out.println("Error processing DOM -- " +e.getMessage());
	            e.printStackTrace(System.out);
	        }
	    }
	    {
	        SAXParser parser = null;
	        SAXParserFactory factory = SAXParserFactory.newInstance();
	        try {
	            parser = factory.newSAXParser();
	            System.out.print("\nSAXParserFactory Instance: " +factory.getClass().getName() +
	                         "\nDSAXParser Instance: " +parser.getClass().getName() + "\n");
	        }
	        catch (Exception e) {
	            System.out.println("Error processing SAX -- " +e.getMessage());
	            e.printStackTrace(System.out);
	        }
	    }
	    {
	        Transformer parser = null;
	        TransformerFactory factory = TransformerFactory.newInstance();
	        try {
	            parser = factory.newTransformer();
	            System.out.print("\nTransformerFactory Instance: " +factory.getClass().getName() +
	                      "\nTransformer Instance: " +parser.getClass().getName() + "\n");
	        }
	        catch (Exception e) {
	            System.out.println("Error processing XSL -- " +e.getMessage());
	            e.printStackTrace(System.out);
	        }
	    }
	    {
	        Schema schema = null;
	        SchemaFactory factory = SchemaFactory.newInstance("http://www.w3.org/2001/XMLSchema");
	        try {
	            schema = factory.newSchema();
	            System.out.print("\nSchemaFactory Instance: " +factory.getClass().getName() +
	                         "\nSchema Instance: " +schema.getClass().getName() + "\n");
	        }
	        catch (Exception e) {
	            System.out.println("Error processing Schema -- " +e.getMessage());
	            e.printStackTrace(System.out);
	        }
	    }
	}
	
	@Override
	public void validateTokenSaml(String xml, String urlSp) throws SAMLException {
		// TODO Auto-generated method stub

	}

}
