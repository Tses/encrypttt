/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.xml.security.samples.transforms;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.samples.DSNamespaceContext;
import org.apache.xml.security.samples.SampleUtils;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * This class demonstrates the use of a Transform forEnveloped Signature.
 *
 * @author Christian Geuer-Pollmann
 * @version %I%, %G%
 */
public class SampleTransformEnvelopedSignature {

    /**
     * Method main
     *
     * @param args
     * @throws Exception
     */
    public static void main(String args[]) throws Exception {
        String inputStr =
            "<?xml version=\"1.0\"?>" + "\n"
            + "<Document xmlns='http://www.w3.org/2000/09/xmldsig#'>" + "\n"
            + "   <Data attr='attrValue'>text in Data</Data>" + "\n"
            + "<Signature Id='SignatureToBeOmitted' xmlns='http://www.w3.org/2000/09/xmldsig#'>" + "\n"
            + "     <SignedInfo>" + "\n"
            + "       <Reference>" + "\n"
            + "         <Transforms>" + "\n"
            // + "           <Transform Algorithm='http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments' />" + "\n"
            + "           <Transform Algorithm='http://www.w3.org/2000/09/xmldsig#enveloped-signature' />" + "\n"
            + "           <Transform Algorithm='http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments' />" + "\n"
            + "         </Transforms>" + "\n"
            + "       </Reference>" + "\n"
            + "     </SignedInfo>" + "\n"
            + "   </Signature>"
            + "   <Signature Id='VisibleSignature' xmlns='http://www.w3.org/2000/09/xmldsig#'>" + "\n"
            + "     <SignedInfo xmlns='http://www.w3.org/2000/09/xmldsig#'>" + "\n"
            + "       <Reference xmlns='http://www.w3.org/2000/09/xmldsig#'>" + "\n"
            + "         <Transforms xmlns='http://www.w3.org/2000/09/xmldsig#'>" + "\n"
            + "           <Transform Algorithm='http://www.w3.org/2000/09/xmldsig#enveloped-signature' />" + "\n"
            + "           <Transform Algorithm='http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments' />" + "\n"
            + "         </Transforms>" + "\n"
            + "       </Reference>" + "\n"
            + "     </SignedInfo>" + "\n"
            + "   </Signature>" + "\n"
            + "</Document>" + "\n"
            ;

        org.apache.xml.security.Init.init();
        javax.xml.parsers.DocumentBuilderFactory dbf =
            javax.xml.parsers.DocumentBuilderFactory.newInstance();

        dbf.setNamespaceAware(true);

        javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
        org.w3c.dom.Document doc =
            db.parse(new java.io.ByteArrayInputStream(inputStr.getBytes()));

        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());

        String expression = "//ds:Signature[@Id='SignatureToBeOmitted']//ds:Transforms";
        Element transformsElem =
            (Element) xpath.evaluate(expression, doc, XPathConstants.NODE);

        Transforms transforms = new Transforms(transformsElem, "memory://");
        XMLSignatureInput input = new XMLSignatureInput((Node) doc);

        // input.setCanonicalizerURI(Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS);

        XMLSignatureInput result = transforms.performTransforms(input);

        System.out.println(new String(result.getBytes()));
    }

}
