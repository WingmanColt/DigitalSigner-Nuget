using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Packaging;
using System.Numerics;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace DigitalSignationLibrary
{
    internal class OfficeOpenXmlSigner:DocumentSigner
    {
        #region Fields
        private const string    RtOfficeDocument      = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument",
                                OfficeObjectID        = "idOfficeObject",
                                SignatureID           = "idPackageSignature",
                                ManifestHashAlgorithm = "http://www.w3.org/2000/09/xmldsig#sha1";
        #endregion

        /// <summary>
        /// Sign.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <param name="output">The output.</param>
        /// <param name="certificate">The certificate.</param>
        public override void Sign(Stream input, Stream output, X509Certificate2 certificate)
        {

            CheckInputOutputAndCertificate(input, output, certificate);
            var tempFile = Path.GetTempFileName();

            using (var fs = File.OpenWrite(tempFile))//copy original stream to a temporary file
            {
                input.CopyTo(fs);
            }

            using (var package = Package.Open(tempFile, FileMode.Open, FileAccess.ReadWrite))//sign that file
            {
                SignAllParts(package, certificate);
            }



            using (var fs = File.OpenRead(tempFile))//copy the signed temprary file to the output stream
            {
                fs.CopyTo(output);
            }


            File.Delete(tempFile);
        }

        /// <summary>
        /// Verify.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <param name="serial">The serial.</param>
        /// <returns></returns>
        public override bool Verify(Stream input, string serial = null)
        {
            if (input == null)
            {
                throw new ArgumentNullException("input");
            }
            using (var package = Package.Open(input, FileMode.Open, FileAccess.Read))
            {

                var mgr = new PackageDigitalSignatureManager(package)
                {
                    CertificateOption = CertificateEmbeddingOption.InSignaturePart
                };

                var result = false;
                foreach (var sig in mgr.Signatures)
                {
                    var verifyResult = mgr.VerifySignatures(true);
                    result = verifyResult == VerifyResult.Success;
                    if (result && !String.IsNullOrWhiteSpace(serial))
                    {
                        var actualSerial = new BigInteger(sig.Signer.GetSerialNumber());
                        var expectedSerial = CertUtil.HexadecimalStringToBigInt(serial);
                        result = actualSerial == expectedSerial;
                    }
                }


                package.Close();
                return result;
            }
        }

        #region Privates
        private void SignAllParts(Package package, X509Certificate2 certificate)
        {
            var partsToSign = new List<Uri>();
            var relationshipsToSign = new List<PackageRelationshipSelector>();

            foreach (var relationship in package.GetRelationshipsByType(RtOfficeDocument))
            {
                AddSignableItems(relationship, partsToSign, relationshipsToSign);
            }

            var mgr = new PackageDigitalSignatureManager(package)
            {
                CertificateOption = CertificateEmbeddingOption.InSignaturePart
            };

            var officeObject = CreateOfficeObject(SignatureID, ManifestHashAlgorithm);
            var officeObjectReference = new Reference("#" + OfficeObjectID);
            mgr.Sign(partsToSign,
                     certificate,
                     relationshipsToSign,
                     SignatureID,
                     new[] { officeObject },
                     new[] { officeObjectReference });



            package.Close();
        }

        private static void AddSignableItems(PackageRelationship relationship, ICollection<Uri> partsToSign, ICollection<PackageRelationshipSelector> relationshipsToSign)
        {
            var selector = new PackageRelationshipSelector(relationship.SourceUri, PackageRelationshipSelectorType.Id, relationship.Id);
            relationshipsToSign.Add(selector);
            if (relationship.TargetMode != TargetMode.Internal)
            {
                return;
            }
            var part = relationship.Package.GetPart(
                PackUriHelper.ResolvePartUri(
                    relationship.SourceUri, relationship.TargetUri));
            if (partsToSign.Contains(part.Uri))
            {
                return;
            }
            partsToSign.Add(part.Uri);
            foreach (var childRelationship in part.GetRelationships())
            {
                AddSignableItems(childRelationship, partsToSign, relationshipsToSign);
            }
        }

        private static DataObject CreateOfficeObject(string signatureID, string manifestHashAlgorithm)
        {
            var document = new XmlDocument();
            document.LoadXml(String.Format(Properties.Resources.OfficeObject, signatureID, manifestHashAlgorithm));
            var officeObject = new DataObject();
            // do not change the order of the following two lines
            officeObject.LoadXml(document.DocumentElement); // resets ID
            officeObject.Id = OfficeObjectID; // required ID, do not change
            return officeObject;
        } 
        #endregion
    }
}