using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace DigitalSignationLibrary
{
    /// <summary>
    /// 
    /// </summary>
    public class XmlSigner:DocumentSigner
    {
        /// <summary>
        /// Sign
        /// </summary>
        /// <param name="input">The input.</param>
        /// <param name="output">The output.</param>
        /// <param name="certificate">The certificate.</param>
        public override void Sign(Stream input, Stream output, X509Certificate2 certificate)
        {
            CheckInputOutputAndCertificate(input, output, certificate);

            using (var rsaKey = (RSACryptoServiceProvider)certificate.PrivateKey)
            {
                var xmlDoc = new XmlDocument { PreserveWhitespace = true };
                xmlDoc.Load(input);
                var signedXml = new SignedXml(xmlDoc) {SigningKey = rsaKey};
                var envelope = new XmlDsigEnvelopedSignatureTransform();
                var reference = new Reference {Uri = ""};
                reference.AddTransform(envelope);
                signedXml.AddReference(reference);
                signedXml.ComputeSignature();
                var xmlDigitalSignature = signedXml.GetXml();
                xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(xmlDigitalSignature, true));
                xmlDoc.Save(output);
            }
        }

        /// <summary>
        /// Verify
        /// </summary>
        /// <param name="input">The input.</param>
        /// <param name="serial">The serial.</param>
        /// <returns></returns>
        public override bool Verify(Stream input, string serial = null)
        {
            var result = false;
            var xmlDoc = new XmlDocument { PreserveWhitespace = true };
            xmlDoc.Load(input);
            var signedXml = new SignedXml(xmlDoc);
            var nodeList = xmlDoc.GetElementsByTagName("Signature");

            if (nodeList.Count > 0)
            {
                foreach (var node in nodeList)
                {
                    signedXml.LoadXml((XmlElement)node);
                    result = signedXml.CheckSignature();
                }
            }
            return result;
        }
    }
}