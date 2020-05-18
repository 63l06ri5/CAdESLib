﻿using System.Collections.Generic;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace CAdESLib.Helpers
{
    public static class DigestAlgorithms
    {

        /** Algorithm available for signatures since PDF 1.3 */
        public const string SHA1 = "SHA-1";

        /** Algorithm available for signatures since PDF 1.6 */
        public const string SHA256 = "SHA-256";

        /** Algorithm available for signatures since PDF 1.7 */
        public const string SHA384 = "SHA-384";

        /** Algorithm available for signatures since PDF 1.7 */
        public const string SHA512 = "SHA-512";

        /** Algorithm available for signatures since PDF 1.7 */
        public const string RIPEMD160 = "RIPEMD160";

        /** Maps the digest IDs with the human-readable name of the digest algorithm. */
        private static readonly Dictionary<string, string> digestNames = new Dictionary<string, string>();

        /** Maps the name of a digest algorithm with its ID. */
        private static readonly Dictionary<string, string> allowedDigests = new Dictionary<string, string>();

        static DigestAlgorithms()
        {
            digestNames["1.2.840.113549.2.5"] = "MD5";
            digestNames["1.2.840.113549.2.2"] = "MD2";
            digestNames["1.3.14.3.2.26"] = "SHA1";
            digestNames["2.16.840.1.101.3.4.2.4"] = "SHA224";
            digestNames["2.16.840.1.101.3.4.2.1"] = "SHA256";
            digestNames["2.16.840.1.101.3.4.2.2"] = "SHA384";
            digestNames["2.16.840.1.101.3.4.2.3"] = "SHA512";
            digestNames["1.3.36.3.2.2"] = "RIPEMD128";
            digestNames["1.3.36.3.2.1"] = "RIPEMD160";
            digestNames["1.3.36.3.2.3"] = "RIPEMD256";
            digestNames["1.2.840.113549.1.1.4"] = "MD5";
            digestNames["1.2.840.113549.1.1.2"] = "MD2";
            digestNames["1.2.840.113549.1.1.5"] = "SHA1";
            digestNames["1.2.840.113549.1.1.14"] = "SHA224";
            digestNames["1.2.840.113549.1.1.11"] = "SHA256";
            digestNames["1.2.840.113549.1.1.12"] = "SHA384";
            digestNames["1.2.840.113549.1.1.13"] = "SHA512";
            digestNames["1.2.840.113549.2.5"] = "MD5";
            digestNames["1.2.840.113549.2.2"] = "MD2";
            digestNames["1.2.840.10040.4.3"] = "SHA1";
            digestNames["2.16.840.1.101.3.4.3.1"] = "SHA224";
            digestNames["2.16.840.1.101.3.4.3.2"] = "SHA256";
            digestNames["2.16.840.1.101.3.4.3.3"] = "SHA384";
            digestNames["2.16.840.1.101.3.4.3.4"] = "SHA512";
            digestNames["1.3.36.3.3.1.3"] = "RIPEMD128";
            digestNames["1.3.36.3.3.1.2"] = "RIPEMD160";
            digestNames["1.3.36.3.3.1.4"] = "RIPEMD256";
            digestNames["1.2.643.2.2.9"] = "GOST3411";

            allowedDigests["MD2"] = "1.2.840.113549.2.2";
            allowedDigests["MD-2"] = "1.2.840.113549.2.2";
            allowedDigests["MD5"] = "1.2.840.113549.2.5";
            allowedDigests["MD-5"] = "1.2.840.113549.2.5";
            allowedDigests["SHA1"] = "1.3.14.3.2.26";
            allowedDigests["SHA-1"] = "1.3.14.3.2.26";
            allowedDigests["SHA224"] = "2.16.840.1.101.3.4.2.4";
            allowedDigests["SHA-224"] = "2.16.840.1.101.3.4.2.4";
            allowedDigests["SHA256"] = "2.16.840.1.101.3.4.2.1";
            allowedDigests["SHA-256"] = "2.16.840.1.101.3.4.2.1";
            allowedDigests["SHA384"] = "2.16.840.1.101.3.4.2.2";
            allowedDigests["SHA-384"] = "2.16.840.1.101.3.4.2.2";
            allowedDigests["SHA512"] = "2.16.840.1.101.3.4.2.3";
            allowedDigests["SHA-512"] = "2.16.840.1.101.3.4.2.3";
            allowedDigests["RIPEMD128"] = "1.3.36.3.2.2";
            allowedDigests["RIPEMD-128"] = "1.3.36.3.2.2";
            allowedDigests["RIPEMD160"] = "1.3.36.3.2.1";
            allowedDigests["RIPEMD-160"] = "1.3.36.3.2.1";
            allowedDigests["RIPEMD256"] = "1.3.36.3.2.3";
            allowedDigests["RIPEMD-256"] = "1.3.36.3.2.3";
            allowedDigests["GOST3411"] = "1.2.643.2.2.9";
        }

        public static IDigest GetMessageDigestFromOid(string digestOid)
        {
            return DigestUtilities.GetDigest(digestOid);
        }

        /**
         * Creates a MessageDigest object that can be used to create a hash.
         * @param hashAlgorithm the algorithm you want to use to create a hash
         * @param provider  the provider you want to use to create the hash
         * @return  a MessageDigest object
         * @throws GeneralSecurityException
         */
        public static IDigest GetMessageDigest(string hashAlgorithm)
        {
            return DigestUtilities.GetDigest(hashAlgorithm);
        }

        /**
         * Creates a hash using a specific digest algorithm and a provider. 
         * @param data  the message of which you want to create a hash
         * @param hashAlgorithm the algorithm used to create the hash
         * @param provider  the provider used to create the hash
         * @return  the hash
         * @throws GeneralSecurityException
         * @throws IOException
         */
        public static byte[] Digest(Stream data, string hashAlgorithm)
        {
            IDigest messageDigest = GetMessageDigest(hashAlgorithm);
            return Digest(data, messageDigest);
        }

        public static byte[] Digest(Stream data, IDigest messageDigest)
        {
            byte[] buf = new byte[8192];
            int n;
            while ((n = data.Read(buf, 0, buf.Length)) > 0)
            {
                messageDigest.BlockUpdate(buf, 0, n);
            }
            byte[] r = new byte[messageDigest.GetDigestSize()];
            messageDigest.DoFinal(r, 0);
            return r;
        }

        /**
         * Gets the digest name for a certain id
         * @param oid   an id (for instance "1.2.840.113549.2.5")
         * @return  a digest name (for instance "MD5")
         */
        public static string GetDigest(string oid)
        {
            if (digestNames.TryGetValue(oid, out string ret))
            {
                return ret;
            }
            else
            {
                return oid;
            }
        }

        /**
         * Returns the id of a digest algorithms that is allowed in PDF,
         * or null if it isn't allowed. 
         * @param name  the name of the digest algorithm
         * @return  an oid
         */
        public static string GetAllowedDigests(string name)
        {
            allowedDigests.TryGetValue(name.ToUpperInvariant(), out string ret);
            return ret;
        }

        public static byte[] Digest(string algo, byte[] b, int offset, int len)
        {
            return Digest(DigestUtilities.GetDigest(algo), b, offset, len);
        }

        public static byte[] Digest(string algo, byte[] b)
        {
            return Digest(DigestUtilities.GetDigest(algo), b, 0, b.Length);
        }

        public static byte[] Digest(IDigest d, byte[] b, int offset, int len)
        {
            d.BlockUpdate(b, offset, len);
            byte[] r = new byte[d.GetDigestSize()];
            d.DoFinal(r, 0);
            return r;
        }

        public static byte[] Digest(IDigest d, byte[] b)
        {
            return Digest(d, b, 0, b.Length);
        }
    }
}
