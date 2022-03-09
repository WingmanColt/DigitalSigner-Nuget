using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace DigitalSignationLibrary
{
    public interface ISignService
    {
        int SignDocumentByUpload(string loadPath, string savePath, string certPath, string Password, StoreName store, StoreLocation location);
        int SignDocumentStored(string loadPath, string savePath, StoreName store, StoreLocation location);
    }

    public class SignService : ISignService
    {

        public int SignDocumentByUpload(string loadPath, string savePath, string certPath, string Password, StoreName store, StoreLocation location)
        {
            if (String.IsNullOrEmpty(loadPath))
            {
                Console.WriteLine("Document load path is not declared.");
                return -1;
            }

            if (String.IsNullOrEmpty(savePath))
            {
                Console.WriteLine("Document save path is not declared.");
                return -1;
            }

            if (String.IsNullOrEmpty(certPath))
            {
                Console.WriteLine("Certification path is not declared.");
                return -1;
            }

            int result = Digitalizer.Cert(loadPath, savePath, certPath, Password, store, location);
            return result;
        }
        public int SignDocumentStored(string loadPath, string savePath, StoreName store, StoreLocation location)
        {
            if (String.IsNullOrEmpty(loadPath))
            {
                Console.WriteLine("Document load path is not declared.");
                return -1;
            }

            if (String.IsNullOrEmpty(savePath))
            {
                Console.WriteLine("Document save path is not declared.");
                return -1;
            }


            int result = Digitalizer.Cert2(loadPath, savePath, store, location);
            return result;
        }
    }

    public class Digitalizer
{
        public static int Cert(string loadPath, string savePath, string certPath, string Password, StoreName store, StoreLocation location)
        {
            try
            {
                var signer = DocumentSigner.For(loadPath);

                var cert = CertUtil.GetFromFile(certPath, Password);
                var serial = cert.SerialNumber;

                signer.Verify(File.OpenRead(loadPath), cert.SerialNumber);
                CertUtil.AddCertificate(cert, store, location);
                signer.Sign(loadPath, savePath, cert);

                Console.Beep();
                return 0;

            }
            catch (Exception ex)
            {

                Console.WriteLine(ex.Message);
                return -1;
            }

        }
        public static int Cert2(string loadPath, string savePath, StoreName store, StoreLocation location)
        {
            try
            {
                var signer = DocumentSigner.For(loadPath);

                var cert = CertUtil.GetByDialog(store, location, true, false);
                if (cert != null)
                {
                    signer.Verify(File.OpenRead(loadPath), cert.SerialNumber);
                    signer.Sign(loadPath, savePath, cert);

                    Console.Beep();
                    return 0;
                }


                Console.WriteLine("Certificate is not valid !");
                return -1;
            }
            catch (Exception ex)
            {

                Console.WriteLine(ex.Message);
                return -1;
            }

        }
    }
    
 }

  

