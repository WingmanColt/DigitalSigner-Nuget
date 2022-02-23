using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace DigitalSignationLibrary
{
    public static class EncryptionHelper
    {
        private static byte[] keyAndIvBytes;

        static EncryptionHelper()
        {
            // You'll need a more secure way of storing this, I hope this isn't
            // the real key
            keyAndIvBytes = UTF8Encoding.UTF8.GetBytes("ComSy542017ComSy542017ComSy54201");
        }

        public static string ByteArrayToHexString(byte[] ba)
        {
            return Convert.ToBase64String(ba);
        }

        public static byte[] StringToByteArray(string hex)
        {
            return Convert.FromBase64String(hex);
        }

        public static string DecodeAndDecrypt(string cipherText)
        {
            string DecodeAndDecrypt = AesDecrypt(StringToByteArray(cipherText));
            return (DecodeAndDecrypt);
        }

        public static string EncryptAndEncode(string plaintext)
        {
            return ByteArrayToHexString(AesEncrypt(plaintext));
        }

        public static string AesDecrypt(Byte[] inputBytes)
        {
            Byte[] outputBytes = inputBytes;

            string plaintext = string.Empty;

            using (MemoryStream memoryStream = new MemoryStream(outputBytes))
            {
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, GetCryptoAlgorithm().CreateDecryptor(keyAndIvBytes, keyAndIvBytes), CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(cryptoStream))
                    {
                        plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }

            return plaintext;
        }

        public static byte[] AesEncrypt(string inputText)
        {
            byte[] inputBytes = UTF8Encoding.UTF8.GetBytes(inputText);//AbHLlc5uLone0D1q

            byte[] result = null;
            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, GetCryptoAlgorithm().CreateEncryptor(keyAndIvBytes, keyAndIvBytes), CryptoStreamMode.Write))
                {
                    cryptoStream.Write(inputBytes, 0, inputBytes.Length);
                    cryptoStream.FlushFinalBlock();

                    result = memoryStream.ToArray();
                }
            }

            return result;
        }


        private static RijndaelManaged GetCryptoAlgorithm()
        {
            RijndaelManaged algorithm = new RijndaelManaged();
            //set the mode, padding and block size
            algorithm.Padding = PaddingMode.None;
            algorithm.Mode = CipherMode.ECB;
            algorithm.KeySize = 256;
            algorithm.BlockSize = 256;
            return algorithm;
        }
    }
}
