using NLog;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Esf;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using CAdESLib.Document.Validation;
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
            byte[] d = DigestUtilities.CalculateDigest(X509ObjectIdentifiers.IdSha1, cert.GetEncoded());
            logger.Info(new DerOctetString(d).ToString());
            OtherHash hash = new OtherHash(d);
            OtherCertID othercertid = new OtherCertID(hash);
            return othercertid;
        }

        /// <summary>
        /// Create a reference to a X509Crl
        /// </summary>
        private static CrlValidatedID MakeCrlValidatedID(X509Crl crl)
        {
            OtherHash hash = new OtherHash(DigestUtilities.CalculateDigest(X509ObjectIdentifiers.IdSha1, crl.GetEncoded()));
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
            byte[] digestValue = DigestUtilities.CalculateDigest
                (X509ObjectIdentifiers.IdSha1, ocspResp.GetEncoded());
            OtherHash hash = new OtherHash(digestValue);
            OcspResponsesID ocsprespid = new OcspResponsesID(new OcspIdentifier(ocspResp.ResponderId
                .ToAsn1Object(), ocspResp.ProducedAt), hash);
            logger.Info("Incorporate OcspResponseId[hash=" + Hex.ToHexString(digestValue) +
                ",producedAt=" + ocspResp.ProducedAt);
            return ocsprespid;
        }

        private IDictionary ExtendUnsignedAttributes(IDictionary unsignedAttrs, X509Certificate signingCertificate, SignatureParameters parameters, DateTime signingTime, ICertificateSource optionalCertificateSource)
        {
            var usedCerts = new List<CertificateAndContext>();
            var validationContext = CertificateVerifier.ValidateCertificate(
                signingCertificate,
                signingTime,
                new CompositeCertificateSource(new ListCertificateSource(parameters.CertificateChain), optionalCertificateSource), usedCerts);
            var completeCertificateRefs = new List<OtherCertID>();
            var completeRevocationRefs = new List<CrlOcspRef>();
            foreach (CertificateAndContext c in validationContext.NeededCertificates)
            {
                if (!c.Equals(signingCertificate))
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
                completeRevocationRefs.Add(new CrlOcspRef(new CrlListID(crlListIdValues.ToArray()), new OcspListID(ocspListIDValues.ToArray()), null));
            }
            unsignedAttrs.Add(PkcsObjectIdentifiers.IdAAEtsCertificateRefs, new BcCms.Attribute(PkcsObjectIdentifiers.IdAAEtsCertificateRefs, new DerSet(new DerSequence(completeCertificateRefs.ToArray()))));
            unsignedAttrs.Add(PkcsObjectIdentifiers.IdAAEtsRevocationRefs, new BcCms.Attribute(PkcsObjectIdentifiers.IdAAEtsRevocationRefs, new DerSet(new DerSequence(completeRevocationRefs.ToArray()))));
            return unsignedAttrs;
        }

        protected internal override SignerInformation ExtendCMSSignature(CmsSignedData signedData, SignerInformation si, SignatureParameters parameters, Document originalData)
        {
            if (si is null)
            {
                throw new ArgumentNullException(nameof(si));
            }

            if (parameters is null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            SignerInformation newSi = base.ExtendCMSSignature(signedData, si, parameters, originalData);
            IDictionary unsignedAttrs = newSi.UnsignedAttributes.ToDictionary();
            CAdESSignature signature = new CAdESSignature(signedData, si.SignerID);
            unsignedAttrs = ExtendUnsignedAttributes(
                unsignedAttrs,
                signature.SigningCertificate,
                parameters,
                signature.SigningTime.Value,
                signature.CertificateSource);
            return SignerInformation.ReplaceUnsignedAttributes(newSi, new BcCms.AttributeTable(unsignedAttrs));
        }
    }
}
