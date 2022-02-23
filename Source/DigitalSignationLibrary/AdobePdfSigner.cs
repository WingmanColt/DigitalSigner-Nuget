using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using iTextSharp.text;
using iTextSharp.text.pdf;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace DigitalSignationLibrary
{
    internal class AdobePdfSigner:DocumentSigner
    {
        //TODO:make this configurable
        private const string SigTextFormat = "Signed By: {0} \r\nDate: {1:MM/dd/yyyy HH:mm:ss}";

        /// <summary>
        /// Sign
        /// </summary>
        /// <param name="input">The input.</param>
        /// <param name="output">The output.</param>
        /// <param name="certificate">The certificate.</param>
        public override void Sign(Stream input, Stream output, X509Certificate2 certificate)
        {
            CheckInputOutputAndCertificate(input, output, certificate);
            PdfReader reader = null;
            try
            {
                reader = new PdfReader(input);
                using (var stamper = PdfStamper.CreateSignature(reader, output, '\0', null, true))
                {
                    var cp = new Org.BouncyCastle.X509.X509CertificateParser();
                    var chain = new[] { cp.ReadCertificate(certificate.RawData) };
                    var sig = stamper.SignatureAppearance;
                    SetSigPosition(sig, reader.AcroFields.GetSignatureNames().Count);
                    SetSigText(sig, chain);
                    SetSigCryptoFromX509(sig, certificate, chain);
                }
            }
            finally
            {
                if (reader != null)
                {
                    reader.Close();
                }
            }
        }

        public override bool Verify(Stream input, string serial = null)
        {
            if (input == null)
            {
                throw new ArgumentNullException("input");
            }

            PdfReader reader = null;
            try
            {
                reader = new PdfReader(input);
                var af = reader.AcroFields;
                var sigNames = af.GetSignatureNames();
                var result = false;
                foreach (var sigName in sigNames)
                {
                    if (af.SignatureCoversWholeDocument(sigName))
                    {
                        var pkcs7 = af.VerifySignature(sigName);
                        result = pkcs7.Verify();
                        if(result && !String.IsNullOrWhiteSpace(serial))
                        {
                            var actualSerial = pkcs7.SigningCertificate.SerialNumber.ToString(16);
                            var expectedSerial = CertUtil.NormalizeSerialString(serial);
                            result = String.Equals(actualSerial, expectedSerial, StringComparison.InvariantCultureIgnoreCase);
                        }
                    }
                }
                return result;
            }
            finally
            {
                if (reader != null)
                {
                    reader.Close();
                }
            }
        }
        
        #region Private
        internal static void SignWithPkcs12KeyStore(string keyStore, string password, string input, string output)
        {
            if (String.IsNullOrEmpty(keyStore))
            {
                throw new ArgumentNullException("keyStore");
            }
            if (String.IsNullOrEmpty(password))
            {
                throw new ArgumentNullException("password");
            }
            if (String.IsNullOrEmpty(input))
            {
                throw new ArgumentNullException("input");
            }
            if (String.IsNullOrEmpty(output))
            {
                throw new ArgumentNullException("output");
            }
            if (!File.Exists(keyStore))
            {
                throw new FileNotFoundException("Keystore is not found or is not a file: " + keyStore, keyStore);
            }
            if (!File.Exists(input))
            {
                throw new FileNotFoundException("Input pdf not found: " + input, input);
            }

            try
            {
                var store = new Pkcs12Store(File.OpenRead(keyStore), password.ToCharArray());
                var pKey = store.Aliases
                    .Cast<string>()
                    .FirstOrDefault(store.IsKeyEntry);
                var key = store.GetKey(pKey).Key;

                var chain = new[] { store.GetCertificate(pKey).Certificate };

                var reader = new PdfReader(input);
                using (var stamper = PdfStamper.CreateSignature(reader, File.OpenWrite(output), '\0', null, true))
                {
                    var sigAppearance = stamper.SignatureAppearance;
                    //Note:note the order of things here
                    SetSigPosition(sigAppearance, reader.AcroFields.GetSignatureNames().Count);
                    SetSigText(sigAppearance, chain);
                    SetSigCryptoFromCipherParam(sigAppearance, key, chain);
                }
            }
            catch (Exception exception)
            {
                throw new Exception("Error while signing pdf file: " + exception.Message, exception);
            }
        }

        private static void SetSigCryptoFromX509(PdfSignatureAppearance sigAppearance, X509Certificate2 card, X509Certificate[] chain)
        {
            sigAppearance.SetCrypto(null, chain, null, PdfSignatureAppearance.WINCER_SIGNED);
            var dic = new PdfSignature(PdfName.ADOBE_PPKMS, PdfName.ADBE_PKCS7_SHA1)
            {
                Date = new PdfDate(sigAppearance.SignDate),
                Name = PdfPKCS7.GetSubjectFields(chain[0]).GetField("CN"),
                Reason = sigAppearance.Reason,
                Location = sigAppearance.Location
            };
            sigAppearance.CryptoDictionary = dic;
            const int csize = 4000;
            var exc = new Dictionary<PdfName, int> { { PdfName.CONTENTS, csize * 2 + 2 } };
            sigAppearance.PreClose(exc);

            HashAlgorithm sha = new SHA1CryptoServiceProvider();
            
            var s = sigAppearance.RangeStream;
            int read;
            var buff = new byte[8192];
            while ((read = s.Read(buff, 0, 8192)) > 0)
            {
                sha.TransformBlock(buff, 0, read, buff, 0);
            }
            sha.TransformFinalBlock(buff, 0, 0);
            var pk = SignMsg(sha.Hash, card, false);

            var outc = new byte[csize];

            var dic2 = new PdfDictionary();

            Array.Copy(pk, 0, outc, 0, pk.Length);

            dic2.Put(PdfName.CONTENTS, new PdfString(outc).SetHexWriting(true));

            sigAppearance.Close(dic2);
        }

        //  Sign the message with the private key of the signer.
        private static byte[] SignMsg(Byte[] msg, X509Certificate2 signerCert, bool detached)
        {
            //  Place message in a ContentInfo object.
            //  This is required to build a SignedCms object.
            var contentInfo = new ContentInfo(msg);

            //  Instantiate SignedCms object with the ContentInfo above.
            //  Has default SubjectIdentifierType IssuerAndSerialNumber.
            var signedCms = new SignedCms(contentInfo, detached);

            //  Formulate a CmsSigner object for the signer.
            var cmsSigner = new CmsSigner(signerCert);

            // Include the following line if the top certificate in the
            // smartcard is not in the trusted list.
            cmsSigner.IncludeOption = X509IncludeOption.EndCertOnly;

            //  Sign the CMS/PKCS #7 message. The second argument is
            //  needed to ask for the pin.
            signedCms.ComputeSignature(cmsSigner, false);

            //  Encode the CMS/PKCS #7 message.
            return signedCms.Encode();
        }

        private static void SetSigCryptoFromCipherParam(PdfSignatureAppearance sigAppearance, ICipherParameters key, X509Certificate[] chain)
        {
            sigAppearance.SetCrypto(key, chain, null, PdfSignatureAppearance.WINCER_SIGNED);
        }

        private static void SetSigText(PdfSignatureAppearance sigAppearance, IList<X509Certificate> chain)
        {
            sigAppearance.SignDate = DateTime.Now;
            var signedBy = PdfPKCS7.GetSubjectFields(chain[0]).GetField("CN");
            var signedOn = sigAppearance.SignDate;
            sigAppearance.Layer2Text = String.Format(SigTextFormat, signedBy, signedOn);
        }

        private static void SetSigPosition(PdfSignatureAppearance sigAppearance, int oldSigCount)
        {
            //Note: original formula from QuangNgV, ll = lower left, ur = upper right, coordinates are calculated relative from the lower left of the pdf page
            float   llx = (100 + 20) * (oldSigCount % 5),
                    lly = (25 + 20) * (oldSigCount / 5),
                    urx = llx + 100,
                    ury = lly + 25;
            sigAppearance.SetVisibleSignature(new Rectangle(llx, lly, urx, ury), 1, null);
        }
        #endregion
    }
}