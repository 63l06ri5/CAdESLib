using CAdESLib.Helpers;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ess;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using System;
using System.Collections.Generic;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;

namespace CAdESLib.Document.Signature.Extensions
{
    public class CAdESProfileBES
    {
        private ICryptographicProvider CryptographicProvider { get; }

        public CAdESProfileBES(ICryptographicProvider cryptographicProvider )
        {
            this.CryptographicProvider = cryptographicProvider;
        }

        private Attribute MakeSigningCertificateAttribute(SignatureParameters parameters)
        {
            var signingCertificate = parameters.SigningCertificate;
            if (signingCertificate is null)
            {
                throw new ArgumentException(nameof(signingCertificate));
            }

            byte[] certHash = CryptographicProvider.CalculateDigest(Helpers.CmsSignedHelper.Instance.GetDigestAlgName(parameters.DigestAlgorithmOID), signingCertificate.GetEncoded());

            if (parameters.DigestAlgorithmOID == DigestAlgorithm.SHA1.OID)
            {
                SigningCertificate sc = new SigningCertificate(new EssCertID(certHash, new IssuerSerial(
                    new GeneralNames(new GeneralName(signingCertificate.IssuerDN)),
                    new DerInteger(signingCertificate.SerialNumber))));
                //SigningCertificate sc = new SigningCertificate(new EssCertID(certHash));
                return new Attribute(PkcsObjectIdentifiers.IdAASigningCertificate, new DerSet(sc));
            }
            else
            {
                EssCertIDv2 essCert = new EssCertIDv2(new AlgorithmIdentifier(new DerObjectIdentifier(parameters.DigestAlgorithmOID)), certHash, new IssuerSerial(
                    new GeneralNames(new GeneralName(signingCertificate.IssuerDN)),
                    new DerInteger(signingCertificate.SerialNumber)));
                SigningCertificateV2 scv2 = new SigningCertificateV2(new EssCertIDv2[] { essCert });
                return new Attribute(PkcsObjectIdentifiers.IdAASigningCertificateV2, new DerSet(scv2));
            }

        }

        private Attribute MakeSigningTimeAttribute(SignatureParameters parameters)
        {
            return new Attribute(PkcsObjectIdentifiers.Pkcs9AtSigningTime, new DerSet(new Org.BouncyCastle.Asn1.X509.Time(parameters.SigningDate.ToUniversalTime())));
        }

        public virtual IDictionary<object, object> GetSignedAttributes(SignatureParameters parameters)
        {
            var signedAttrs = new Dictionary<object, object>();
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
