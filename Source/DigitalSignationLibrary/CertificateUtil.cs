using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography.X509Certificates;

namespace DigitalSignationLibrary
{
    /// <summary>
    /// Certificate utilities
    /// </summary>
    public static class CertUtil
    {
        #region Retrieval
        /// <summary>
        /// Gets the certificates.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="selector">The selector.</param>
        /// <param name="storeName">Name of the store.</param>
        /// <param name="storeLocation">The store location.</param>
        /// <param name="validOnly">if set to <c>true</c> [valid only].</param>
        /// <param name="requirePrivateKey">if set to <c>true</c> [require private key].</param>
        /// <returns></returns>
        public static IEnumerable<T> GetAll<T>(Func<X509Certificate2, T> selector, StoreName storeName = StoreName.My, StoreLocation storeLocation = StoreLocation.CurrentUser, bool validOnly = false, bool requirePrivateKey = false)
        {
            if (selector == null)
            {
                throw new ArgumentNullException("selector");
            }
            X509Store store = null;
            try
            {
                store = new X509Store(storeName, storeLocation);
                store.Open(OpenFlags.ReadOnly); 
                return store.Certificates
                            .Cast<X509Certificate2>()
                            .Where(cert=>requirePrivateKey ? cert.HasPrivateKey : true)
                            .Select(selector)
                            .ToArray();
            }
            finally
            {
                if (store != null)
                {
                    store.Close();
                }
            }
        }

        /// <summary>
        /// Gets a certificate with the specified serial number.
        /// </summary>
        /// <param name="serial">The serial.</param>
        /// <param name="storeName">Name of the store.</param>
        /// <param name="storeLocation">The store location.</param>
        /// <param name="validOnly">if set to <c>true</c> [valid only].</param>
        /// <param name="requirePrivateKey">if set to <c>true</c> [require private key].</param>
        /// <returns></returns>
        public static X509Certificate2 GetBySerial(string serial, StoreName storeName = StoreName.My, StoreLocation storeLocation = StoreLocation.CurrentUser, bool validOnly = false, bool requirePrivateKey = false)
        {
            if (String.IsNullOrEmpty(serial))
            {
                throw new ArgumentNullException("serial");
            }
            X509Store store = null;
            try
            {
                store = new X509Store(storeName, storeLocation);
                store.Open(OpenFlags.ReadOnly);
                return store.Certificates
                            .Find(X509FindType.FindBySerialNumber, serial, validOnly)
                            .Cast<X509Certificate2>()
                            .Where(c=>requirePrivateKey ? c.HasPrivateKey : true)
                            .FirstOrDefault();
            }
            finally
            {
                if (store != null)
                {
                    store.Close();
                }
            }
        }

        /// <summary>
        /// Gets the certificate from file.
        /// </summary>
        /// <param name="fileName">Name of the file.</param>
        /// <param name="password">The password.</param>
        /// <returns></returns>
        public static X509Certificate2 GetFromFile(string fileName, string password)
        {
                return new X509Certificate2(fileName, password);
        }

        /// <summary>
        /// Show a dialog and have the user select a certificate to sign.
        /// </summary>
        /// <returns></returns>
        public static X509Certificate2 GetByDialog(StoreName storeName = StoreName.My, StoreLocation storeLocation = StoreLocation.CurrentUser, bool validOnly = false, bool requirePrivateKey = false)
        {
            X509Store store = null;
            X509Certificate2 result;
            try
            {
                store = new X509Store(storeName, storeLocation);
                store.Open(OpenFlags.ReadOnly);
                var selections = store.Certificates;
                if (requirePrivateKey)
                {
                    var filtered = selections
                                    .Cast<X509Certificate2>()
                                    .Where(cert => cert.HasPrivateKey)
                                    .ToArray();
                    selections = new X509Certificate2Collection(filtered);
                }
                var selection = X509Certificate2UI.SelectFromCollection(selections, "Certificates", "Choose Sign", X509SelectionFlag.SingleSelection);
                result = selection.Count == 0
                             ? null
                             : selection
                                    .Cast<X509Certificate2>()
                                    .Where(cert => cert.NotAfter >= DateTime.Now)
                                    .FirstOrDefault();
            }
            finally
            {
                if (store != null)
                {
                    store.Close();
                }
            }
            return result;
        } 
        #endregion

        #region Misc
        /// <summary>
        /// Convert from hexadecimal string to big integer.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <returns></returns>
        public static BigInteger HexadecimalStringToBigInt(string input)
        {
            return BigInteger.Parse(NormalizeSerialString(input), System.Globalization.NumberStyles.HexNumber);
        }

        /// <summary>
        /// Convert from big integer to hexadecimal string.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <returns></returns>
        public static string BigIntToHexadecimalString(BigInteger input)
        {
            return input.ToString("x");
        }

        /// <summary>
        /// Normalizes the serial string.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <returns></returns>
        public static string NormalizeSerialString(string input)
        {
            return input != null ? input.Replace(" ", "").ToUpperInvariant() : String.Empty;
        }
        /// <summary>
        /// Normalizes the serial string.
        /// </summary>
        /// <returns></returns>
        public static void AddCertificate(X509Certificate2 cert, StoreName storeName = StoreName.My, StoreLocation storeLocation = StoreLocation.CurrentUser)
        {
            X509Store store = null;
            try
            {
                store = new X509Store(storeName, storeLocation);
                store.Open(OpenFlags.ReadWrite);
                store.Add(cert);
            }
            finally
            {
                if (store != null)
                {
                    store.Close();
                }
            }
        }
        /// <summary>
        /// Normalizes the serial string.
        /// </summary>
        /// <returns></returns>
        public static void RemoveCertificate(string serial, StoreName storeName = StoreName.My, StoreLocation storeLocation = StoreLocation.CurrentUser)
        {
            if (String.IsNullOrEmpty(serial))
            {
                throw new ArgumentNullException("serial");
            }
            X509Store store = null;
            try
            {
                store = new X509Store(storeName, storeLocation);
                store.Open(OpenFlags.ReadWrite);
                var existings = store.Certificates.Find(X509FindType.FindBySerialNumber, serial, false);
                if (existings.Count == 0)
                {
                    return;
                }
                store.RemoveRange(existings);
            }
            finally
            {
                if (store != null)
                {
                    store.Close();
                }
            }
        }
        #endregion
    }
}