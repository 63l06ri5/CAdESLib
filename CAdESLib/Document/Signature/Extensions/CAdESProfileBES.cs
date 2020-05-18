using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Esf;
using Org.BouncyCastle.Asn1.Ess;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;
using System.Collections.Generic;
using System.Text;

namespace CAdESLib.Document.Signature.Extensions
{
    public class CAdESProfileBES
    {
        public CAdESProfileBES()
        {
        }

        private Attribute MakeSigningCertificateAttribute(SignatureParameters parameters)
        {
            byte[] certHash = DigestUtilities.CalculateDigest(Helpers.CmsSignedHelper.Instance.GetDigestAlgName(parameters.DigestAlgorithmOID), parameters.SigningCertificate.GetEncoded());

            if (parameters.DigestAlgorithmOID == DigestAlgorithm.SHA1.OID)
            {
                SigningCertificate sc = new SigningCertificate(new EssCertID(certHash, new IssuerSerial(
                    new GeneralNames(new GeneralName(parameters.SigningCertificate.IssuerDN)),
                    new DerInteger(parameters.SigningCertificate.SerialNumber))));
                //SigningCertificate sc = new SigningCertificate(new EssCertID(certHash));
                return new Attribute(PkcsObjectIdentifiers.IdAASigningCertificate, new DerSet(sc));
            }
            else
            {
                EssCertIDv2 essCert = new EssCertIDv2(new AlgorithmIdentifier(new DerObjectIdentifier(parameters.DigestAlgorithmOID)), certHash, new IssuerSerial(
                    new GeneralNames(new GeneralName(parameters.SigningCertificate.IssuerDN)),
                    new DerInteger(parameters.SigningCertificate.SerialNumber)));
                SigningCertificateV2 scv2 = new SigningCertificateV2(new EssCertIDv2[] { essCert });
                return new Attribute(PkcsObjectIdentifiers.IdAASigningCertificateV2, new DerSet(scv2));
            }

        }

        private Attribute MakeSigningTimeAttribute(SignatureParameters parameters)
        {
            return new Attribute(PkcsObjectIdentifiers.Pkcs9AtSigningTime, new DerSet(new Org.BouncyCastle.Asn1.X509.Time(parameters.SigningDate)));
        }

        private Attribute MakeSignerAttrAttribute(SignatureParameters parameters)
        {
            DerOctetString[] roles = new DerOctetString[1];
            roles[0] = new DerOctetString(Encoding.UTF8.GetBytes(parameters.ClaimedSignerRole));
            return new Attribute(PkcsObjectIdentifiers.IdAAEtsSignerAttr, new DerSet(new SignerAttribute
                (new DerSequence(roles))));
        }

        public virtual IDictionary<DerObjectIdentifier, Asn1Encodable> GetSignedAttributes(SignatureParameters parameters)
        {
            var signedAttrs = new Dictionary<DerObjectIdentifier, Asn1Encodable>();
            Attribute signingCertificateReference = MakeSigningCertificateAttribute(parameters);
            signedAttrs.Add(signingCertificateReference.AttrType, signingCertificateReference);
            signedAttrs.Add(PkcsObjectIdentifiers.Pkcs9AtSigningTime, MakeSigningTimeAttribute(parameters));

            return signedAttrs;
        }

        public virtual IDictionary<DerObjectIdentifier, Asn1Encodable> GetUnsignedAttributes(SignatureParameters parameters)
        {
            return new Dictionary<DerObjectIdentifier, Asn1Encodable>();
        }
    }
}
