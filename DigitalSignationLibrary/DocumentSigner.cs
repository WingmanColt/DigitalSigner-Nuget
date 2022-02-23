using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace DigitalSignationLibrary
{
    /// <summary>
    /// A document signer
    /// </summary>
    public abstract class DocumentSigner
    {
        /// <summary>
        /// Sign
        /// </summary>
        /// <param name="input">The input.</param>
        /// <param name="output">The output.</param>
        /// <param name="certificate">The certificate.</param>
        public abstract void Sign(Stream input, Stream output, X509Certificate2 certificate);

        /// <summary>
        /// Verifies
        /// </summary>
        /// <param name="input">The input.</param>
        /// <param name="serial">The serial.</param>
        /// <returns></returns>
        public abstract bool Verify(Stream input, string serial = null);

        /// <summary>
        /// Signs the file.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <param name="output">The output.</param>
        /// <param name="certificate">The certificate.</param>
        public void Sign(string input, string output, X509Certificate2 certificate)
        {
            // Thread.Sleep(3000);
            using (var iStream = File.OpenRead(input))
            using (var oStream = File.OpenWrite(output))
            {
             Sign(iStream, oStream, certificate);
            }

        }
      
        /// <summary>
        /// Initialize a signer for the specified file name.
        /// </summary>
        /// <param name="type">The type.</param>
        /// <returns></returns>
        public static DocumentSigner For(string type)
        {
            type = NormalizeExtension(type);
            DocumentSigner result;
            switch(type)
            {
                case "pdf":
                    result = new AdobePdfSigner();
                    break;
                case "xlsx":
                case "docx":
                case "pptx":
                    result = new OfficeOpenXmlSigner();
                    break;
                case "xml":
                    result = new XmlSigner();
                    break;
                default:
                    result = null;
                    break;
            }
            return result;
        }

        #region Misc
        /// <summary>
        /// Normalizes the extension.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <returns></returns>
        private static string NormalizeExtension(string input)
        {
            var result = input == null ? "" : input.Trim().ToLower();
            var dotPos = result.LastIndexOf(".");
            if (dotPos != -1 && dotPos < result.Length)
            {
                result = result.Substring(dotPos + 1, result.Length - (dotPos + 1));
            }
            return result;
        }

        /// <summary>
        /// Checks the input output and certificate.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <param name="output">The output.</param>
        /// <param name="certificate">The certificate.</param>
        protected static void CheckInputOutputAndCertificate(Stream input, Stream output, X509Certificate2 certificate)
        {
            if (input == null)
            {
                throw new ArgumentNullException("input");
            }
            if (output == null)
            {
                throw new ArgumentNullException("output");
            }
            if (certificate == null)
            {
                throw new ArgumentNullException("certificate");
            }
            if (!certificate.HasPrivateKey)
            {
                throw new Exception("No private key");
            }
        } 
        #endregion
    }
}