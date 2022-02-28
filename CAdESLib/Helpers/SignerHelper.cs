using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Eac;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Cms;
using System.Collections;
using System.Collections.Generic;

namespace CAdESLib.Helpers
{
    /// <summary>
    /// Came from https://github.com/bcgit/bc-csharp
    /// </summary>
    public class CmsSignedHelper
    {
        public static readonly CmsSignedHelper Instance = new CmsSignedHelper();

        private static readonly string EncryptionECDsaWithSha1 = X9ObjectIdentifiers.ECDsaWithSha1.Id;
        private static readonly string EncryptionECDsaWithSha224 = X9ObjectIdentifiers.ECDsaWithSha224.Id;
        private static readonly string EncryptionECDsaWithSha256 = X9ObjectIdentifiers.ECDsaWithSha256.Id;
        private static readonly string EncryptionECDsaWithSha384 = X9ObjectIdentifiers.ECDsaWithSha384.Id;
        private static readonly string EncryptionECDsaWithSha512 = X9ObjectIdentifiers.ECDsaWithSha512.Id;

        private static readonly IDictionary encryptionAlgs = new Hashtable();
        private static readonly IDictionary digestAlgs = new Hashtable();
        private static readonly IDictionary digestAliases = new Hashtable();

        private static readonly ISet<string> noParams = new HashSet<string>();
        private static readonly IDictionary ecAlgorithms = new Hashtable();

        private static void AddEntries(DerObjectIdentifier oid, string digest, string encryption)
        {
            string alias = oid.Id;
            digestAlgs.Add(alias, digest);
            encryptionAlgs.Add(alias, encryption);
        }

        static CmsSignedHelper()
        {
            AddEntries(NistObjectIdentifiers.DsaWithSha224, "SHA224", "DSA");
            AddEntries(NistObjectIdentifiers.DsaWithSha256, "SHA256", "DSA");
            AddEntries(NistObjectIdentifiers.DsaWithSha384, "SHA384", "DSA");
            AddEntries(NistObjectIdentifiers.DsaWithSha512, "SHA512", "DSA");
            AddEntries(OiwObjectIdentifiers.DsaWithSha1, "SHA1", "DSA");
            AddEntries(OiwObjectIdentifiers.MD4WithRsa, "MD4", "RSA");
            AddEntries(OiwObjectIdentifiers.MD4WithRsaEncryption, "MD4", "RSA");
            AddEntries(OiwObjectIdentifiers.MD5WithRsa, "MD5", "RSA");
            AddEntries(OiwObjectIdentifiers.Sha1WithRsa, "SHA1", "RSA");
            AddEntries(PkcsObjectIdentifiers.MD2WithRsaEncryption, "MD2", "RSA");
            AddEntries(PkcsObjectIdentifiers.MD4WithRsaEncryption, "MD4", "RSA");
            AddEntries(PkcsObjectIdentifiers.MD5WithRsaEncryption, "MD5", "RSA");
            AddEntries(PkcsObjectIdentifiers.Sha1WithRsaEncryption, "SHA1", "RSA");
            AddEntries(PkcsObjectIdentifiers.Sha224WithRsaEncryption, "SHA224", "RSA");
            AddEntries(PkcsObjectIdentifiers.Sha256WithRsaEncryption, "SHA256", "RSA");
            AddEntries(PkcsObjectIdentifiers.Sha384WithRsaEncryption, "SHA384", "RSA");
            AddEntries(PkcsObjectIdentifiers.Sha512WithRsaEncryption, "SHA512", "RSA");
            AddEntries(X9ObjectIdentifiers.ECDsaWithSha1, "SHA1", "ECDSA");
            AddEntries(X9ObjectIdentifiers.ECDsaWithSha224, "SHA224", "ECDSA");
            AddEntries(X9ObjectIdentifiers.ECDsaWithSha256, "SHA256", "ECDSA");
            AddEntries(X9ObjectIdentifiers.ECDsaWithSha384, "SHA384", "ECDSA");
            AddEntries(X9ObjectIdentifiers.ECDsaWithSha512, "SHA512", "ECDSA");
            AddEntries(X9ObjectIdentifiers.IdDsaWithSha1, "SHA1", "DSA");
            AddEntries(EacObjectIdentifiers.id_TA_ECDSA_SHA_1, "SHA1", "ECDSA");
            AddEntries(EacObjectIdentifiers.id_TA_ECDSA_SHA_224, "SHA224", "ECDSA");
            AddEntries(EacObjectIdentifiers.id_TA_ECDSA_SHA_256, "SHA256", "ECDSA");
            AddEntries(EacObjectIdentifiers.id_TA_ECDSA_SHA_384, "SHA384", "ECDSA");
            AddEntries(EacObjectIdentifiers.id_TA_ECDSA_SHA_512, "SHA512", "ECDSA");
            AddEntries(EacObjectIdentifiers.id_TA_RSA_v1_5_SHA_1, "SHA1", "RSA");
            AddEntries(EacObjectIdentifiers.id_TA_RSA_v1_5_SHA_256, "SHA256", "RSA");
            AddEntries(EacObjectIdentifiers.id_TA_RSA_PSS_SHA_1, "SHA1", "RSAandMGF1");
            AddEntries(EacObjectIdentifiers.id_TA_RSA_PSS_SHA_256, "SHA256", "RSAandMGF1");
            AddEntries(CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94, "GOST3411", "GOST3410");
            AddEntries(CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001, "GOST3411", "ECGOST3410");
            AddEntries(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256, "GOST3411-2012-256", "ECGOST3410");
            AddEntries(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512, "GOST3411-2012-512", "ECGOST3410");

            encryptionAlgs.Add(X9ObjectIdentifiers.IdDsa.Id, "DSA");
            encryptionAlgs.Add(PkcsObjectIdentifiers.RsaEncryption.Id, "RSA");
            encryptionAlgs.Add(TeleTrusTObjectIdentifiers.TeleTrusTRsaSignatureAlgorithm.Id, "RSA");
            encryptionAlgs.Add(X509ObjectIdentifiers.IdEARsa.Id, "RSA");
            encryptionAlgs.Add(CmsSignedGenerator.EncryptionRsaPss, "RSAandMGF1");
            encryptionAlgs.Add(CryptoProObjectIdentifiers.GostR3410x94.Id, "GOST3410");
            encryptionAlgs.Add(CryptoProObjectIdentifiers.GostR3410x2001.Id, "ECGOST3410");
            encryptionAlgs.Add("1.3.6.1.4.1.5849.1.6.2", "ECGOST3410");
            encryptionAlgs.Add("1.3.6.1.4.1.5849.1.1.5", "GOST3410");
            encryptionAlgs.Add(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256.Id, "ECGOST3410");
            encryptionAlgs.Add(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512.Id, "ECGOST3410");

            digestAlgs.Add(PkcsObjectIdentifiers.MD2.Id, "MD2");
            digestAlgs.Add(PkcsObjectIdentifiers.MD4.Id, "MD4");
            digestAlgs.Add(PkcsObjectIdentifiers.MD5.Id, "MD5");
            digestAlgs.Add(OiwObjectIdentifiers.IdSha1.Id, "SHA1");
            digestAlgs.Add(NistObjectIdentifiers.IdSha224.Id, "SHA224");
            digestAlgs.Add(NistObjectIdentifiers.IdSha256.Id, "SHA256");
            digestAlgs.Add(NistObjectIdentifiers.IdSha384.Id, "SHA384");
            digestAlgs.Add(NistObjectIdentifiers.IdSha512.Id, "SHA512");
            digestAlgs.Add(TeleTrusTObjectIdentifiers.RipeMD128.Id, "RIPEMD128");
            digestAlgs.Add(TeleTrusTObjectIdentifiers.RipeMD160.Id, "RIPEMD160");
            digestAlgs.Add(TeleTrusTObjectIdentifiers.RipeMD256.Id, "RIPEMD256");
            digestAlgs.Add(CryptoProObjectIdentifiers.GostR3411.Id, "GOST3411");
            digestAlgs.Add("1.3.6.1.4.1.5849.1.2.1", "GOST3411");
            digestAlgs.Add(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256.Id, "GOST3411-2012-256");
            digestAlgs.Add(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512.Id, "GOST3411-2012-512");

            digestAliases.Add("SHA1", new string[] { "SHA-1" });
            digestAliases.Add("SHA224", new string[] { "SHA-224" });
            digestAliases.Add("SHA256", new string[] { "SHA-256" });
            digestAliases.Add("SHA384", new string[] { "SHA-384" });
            digestAliases.Add("SHA512", new string[] { "SHA-512" });

            noParams.Add(CmsSignedGenerator.EncryptionDsa);
            noParams.Add(EncryptionECDsaWithSha1);
            noParams.Add(EncryptionECDsaWithSha224);
            noParams.Add(EncryptionECDsaWithSha256);
            noParams.Add(EncryptionECDsaWithSha384);
            noParams.Add(EncryptionECDsaWithSha512);

            ecAlgorithms.Add(CmsSignedGenerator.DigestSha1, EncryptionECDsaWithSha1);
            ecAlgorithms.Add(CmsSignedGenerator.DigestSha224, EncryptionECDsaWithSha224);
            ecAlgorithms.Add(CmsSignedGenerator.DigestSha256, EncryptionECDsaWithSha256);
            ecAlgorithms.Add(CmsSignedGenerator.DigestSha384, EncryptionECDsaWithSha384);
            ecAlgorithms.Add(CmsSignedGenerator.DigestSha512, EncryptionECDsaWithSha512);
        }

        /**
        * Return the digest algorithm using one of the standard JCA string
        * representations rather than the algorithm identifier (if possible).
        */
        public string GetDigestAlgName(
            string digestAlgOid)
        {
            string algName = (string)digestAlgs[digestAlgOid];

            if (algName != null)
            {
                return algName;
            }

            return digestAlgOid;
        }

        /**
        * Return the digest encryption algorithm using one of the standard
        * JCA string representations rather than the algorithm identifier (if
        * possible).
        */
        public string GetEncryptionAlgName(
            string encryptionAlgOid)
        {
            string algName = (string)encryptionAlgs[encryptionAlgOid];

            if (algName != null)
            {
                return algName;
            }

            return encryptionAlgOid;
        }
    }
}
