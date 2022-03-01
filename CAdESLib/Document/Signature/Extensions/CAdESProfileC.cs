using CAdESLib.Document.Validation;
using NLog;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Esf;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;
using System;
using System.Collections;
using System.Collections.Generic;
using BcCms = Org.BouncyCastle.Asn1.Cms;

namespace CAdESLib.Document.Signature.Extensions
{
    /// <summary>
    /// This class holds the CAdES-C signature profile; it supports the inclusion of the mandatory unsigned
    /// id-aa-ets-certificateRefs and id-aa-ets-revocationRefs attributes as specified in ETSI TS 101 733 V1.8.1, clauses
    /// 6.2.1 & 6.2.2.
    /// </summary>

    public class CAdESProfileC : CAdESProfileT
    {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        public ICertificateVerifier CertificateVerifier { get; set; }


        /// <summary>
        /// Create a reference to a X509Certificate
        /// </summary>
        private static OtherCertID MakeOtherCertID(X509Certificate cert)
        {
            var hashAlg = X509ObjectIdentifiers.IdSha1;
            byte[] d = DigestUtilities.CalculateDigest(hashAlg, cert.GetEncoded());
            logger.Info(new DerOctetString(d).ToString());
            OtherHash hash = new OtherHash(new OtherHashAlgAndValue(new AlgorithmIdentifier(hashAlg), d));
            OtherCertID othercertid = new OtherCertID(hash);
            return othercertid;
        }

        /// <summary>
        /// Create a reference to a X509Crl
        /// </summary>
        private static CrlValidatedID MakeCrlValidatedID(X509Crl crl)
        {
            var hashAlg = X509ObjectIdentifiers.IdSha1;
            OtherHash hash = new OtherHash(new OtherHashAlgAndValue(new AlgorithmIdentifier(hashAlg), DigestUtilities.CalculateDigest(hashAlg, crl.GetEncoded())));
            BigInteger crlnumber;
            CrlIdentifier crlid;
            DerObjectIdentifier crlExt = new DerObjectIdentifier("2.5.29.20");
            if (crl.GetExtensionValue(crlExt) != null)
            {
                crlnumber = new DerInteger(crl.GetExtensionValue(crlExt).GetDerEncoded()).PositiveValue;
                crlid = new CrlIdentifier(crl.IssuerDN, crl.ThisUpdate, crlnumber);
            }
            else
            {
                crlid = new CrlIdentifier(crl.IssuerDN, crl.ThisUpdate);
            }
            CrlValidatedID crlvid = new CrlValidatedID(hash, crlid);
            return crlvid;
        }

        /// <summary>
        /// Create a reference on a OcspResp
        /// </summary>
        private static OcspResponsesID MakeOcspResponsesID(BasicOcspResp ocspResp)
        {
            var hashAlg = X509ObjectIdentifiers.IdSha1;
            byte[] digestValue = DigestUtilities.CalculateDigest
                (hashAlg, ocspResp.GetEncoded());
            OtherHash hash = new OtherHash(new OtherHashAlgAndValue(new AlgorithmIdentifier(hashAlg), digestValue));
            OcspResponsesID ocsprespid = new OcspResponsesID(new OcspIdentifier(ocspResp.ResponderId
                .ToAsn1Object(), ocspResp.ProducedAt), hash);
            logger.Info("Incorporate OcspResponseId[hash=" + Hex.ToHexString(digestValue) +
                ",producedAt=" + ocspResp.ProducedAt);
            return ocsprespid;
        }

        private (IDictionary, IValidationContext) ExtendUnsignedAttributes(IDictionary unsignedAttrs, X509Certificate signingCertificate, SignatureParameters parameters, DateTime signingTime, ICertificateSource optionalCertificateSource, IValidationContext validationContext)
        {
            var usedCerts = new List<CertificateAndContext>();
            validationContext = CertificateVerifier.ValidateCertificate(
                signingCertificate,
                signingTime,
                new CompositeCertificateSource(new ListCertificateSource(parameters.CertificateChain), optionalCertificateSource), usedCerts, inContext: validationContext);
            BcCms.Attribute timeStampAttr = new BcCms.AttributeTable(unsignedAttrs)[PkcsObjectIdentifiers.IdAASignatureTimeStampToken];
            if (timeStampAttr != null)
            {
                var value = timeStampAttr.AttrValues[0].GetDerEncoded();
                var token = new TimestampToken(new TimeStampToken(new CmsSignedData(value)), TimestampToken.TimestampType.SIGNATURE_TIMESTAMP);
                validationContext.ValidateTimestamp(token, optionalCertificateSource, null, null, usedCerts);
            }

            var completeCertificateRefs = new List<OtherCertID>();
            var completeRevocationRefs = new List<CrlOcspRef>();
            foreach (CertificateAndContext c in validationContext.NeededCertificates)
            {
                if (!c.Certificate.Equals(signingCertificate))
                {
                    completeCertificateRefs.Add(MakeOtherCertID(c.Certificate));
                }
                List<CrlValidatedID> crlListIdValues = new List<CrlValidatedID>();
                List<OcspResponsesID> ocspListIDValues = new List<OcspResponsesID>();
                foreach (X509Crl relatedcrl in validationContext.GetRelatedCRLs(c))
                {
                    crlListIdValues.Add(MakeCrlValidatedID(relatedcrl));
                }
                foreach (BasicOcspResp relatedocspresp in validationContext.GetRelatedOCSPResp(c))
                {
                    ocspListIDValues.Add(MakeOcspResponsesID(relatedocspresp));
                }
                completeRevocationRefs.Add(new CrlOcspRef(crlListIdValues.Count == 0 || ocspListIDValues.Count != 0 ? null : new CrlListID(crlListIdValues.ToArray()), ocspListIDValues.Count == 0 ? null : new OcspListID(ocspListIDValues.ToArray()), null));
            }
            unsignedAttrs.Add(PkcsObjectIdentifiers.IdAAEtsCertificateRefs, new BcCms.Attribute(PkcsObjectIdentifiers.IdAAEtsCertificateRefs, new DerSet(new DerSequence(completeCertificateRefs.ToArray()))));
            unsignedAttrs.Add(PkcsObjectIdentifiers.IdAAEtsRevocationRefs, new BcCms.Attribute(PkcsObjectIdentifiers.IdAAEtsRevocationRefs, new DerSet(new DerSequence(completeRevocationRefs.ToArray()))));
            return (unsignedAttrs, validationContext);
        }

        protected internal override (SignerInformation, IValidationContext) ExtendCMSSignature(CmsSignedData signedData, SignerInformation si, SignatureParameters parameters, IDocument originalData)
        {
            if (si is null)
            {
                throw new ArgumentNullException(nameof(si));
            }

            if (parameters is null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            var (newSi, validationContext) = base.ExtendCMSSignature(signedData, si, parameters, originalData);
            IDictionary unsignedAttrs = newSi.UnsignedAttributes.ToDictionary();
            CAdESSignature signature = new CAdESSignature(signedData, si.SignerID);
            (unsignedAttrs, validationContext) = ExtendUnsignedAttributes(
                unsignedAttrs,
                signature.SigningCertificate,
                parameters,
                signature.SigningTime.Value,
                signature.CertificateSource,
                validationContext);
            return (SignerInformation.ReplaceUnsignedAttributes(newSi, new BcCms.AttributeTable(unsignedAttrs)), validationContext);
        }
    }
}
