using CAdESLib.Document.Validation;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Esf;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;
using System;
using System.Collections;
using System.Collections.Generic;
using BcCms = Org.BouncyCastle.Asn1.Cms;

namespace CAdESLib.Document.Signature.Extensions
{
    /// <summary>
    /// This class holds the CAdES-X signature profiles; it supports the inclusion of a combination of the unsigned
    /// attributes id-aa-ets-escTimeStamp, id-aa-ets-certCRLTimestamp, id-aa-ets-certValues, id-aa-ets-revocationValues as
    /// defined in ETSI TS 101 733 V1.8.1, clause 6.3.
    /// </summary>

    public class CAdESProfileXL : CAdESProfileX
    {
        /// <summary>
        /// Sets the type of the CAdES-X signature (Type 1 with id-aa-ets-escTimeStamp or Type 2 with
        /// id-aa-ets-certCRLTimestamp)
        /// </summary>
        /// <param>
        /// to type to set, 1 or 2
        /// </param>
        public override void SetExtendedValidationType(int extendedValidationType)
        {
            this.extendedValidationType = extendedValidationType;
        }

        private IDictionary ExtendUnsignedAttributes(IDictionary unsignedAttrs, X509Certificate signingCertificate, DateTime signingDate, ICertificateSource optionalCertificateSource, IValidationContext validationContext)
        {
            List<X509CertificateStructure> certificateValues = new List<X509CertificateStructure>();
            List<CertificateList> crlValues = new List<CertificateList>();
            List<BasicOcspResponse> ocspValues = new List<BasicOcspResponse>();
            foreach (CertificateAndContext c in validationContext.NeededCertificates)
            {
                certificateValues.Add(X509CertificateStructure.GetInstance(((Asn1Sequence)Asn1Object.FromByteArray(c.Certificate.GetEncoded()))));
            }
            foreach (var relatedcrl in validationContext.NeededCRLTokens)
            {
                crlValues.Add(CertificateList.GetInstance((Asn1Sequence)Asn1Object.FromByteArray(relatedcrl.GetX509crl().GetEncoded())));
            }
            foreach (var relatedocspresp in validationContext.NeededOCSPRespTokens)
            {
                ocspValues.Add((BasicOcspResponse.GetInstance((Asn1Sequence)Asn1Object.FromByteArray(relatedocspresp.GetOcspResp().GetEncoded()))));
            }
            RevocationValues revocationValues = new RevocationValues(crlValues.ToArray(), ocspValues.ToArray(), null);
            unsignedAttrs.Add(PkcsObjectIdentifiers.IdAAEtsRevocationValues, new BcCms.Attribute(PkcsObjectIdentifiers.IdAAEtsRevocationValues, new DerSet(revocationValues)));
            unsignedAttrs.Add(PkcsObjectIdentifiers.IdAAEtsCertValues, new BcCms.Attribute(PkcsObjectIdentifiers.IdAAEtsCertValues, new DerSet(new DerSequence(certificateValues.ToArray()))));

            return unsignedAttrs;
        }

        protected internal override (SignerInformation, IValidationContext) ExtendCMSSignature(CmsSignedData signedData, SignerInformation si, SignatureParameters parameters, IDocument originalData)
        {
            if (parameters is null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            var (newSi, validationContext) = base.ExtendCMSSignature(signedData, si, parameters, originalData);
            si = newSi;
            IDictionary unsignedAttrs = si.UnsignedAttributes.ToDictionary();
            CAdESSignature signature = new CAdESSignature(signedData, si.SignerID);
            DateTime signingTime = signature.SigningTime.Value;
            if (signingTime == null)
            {
                signingTime = parameters.SigningDate;
            }
            if (signingTime == null)
            {
                signingTime = DateTime.Now;
            }
            unsignedAttrs = ExtendUnsignedAttributes(unsignedAttrs, signature.SigningCertificate, signingTime, signature.CertificateSource, validationContext);
            SignerInformation newsi = SignerInformation.ReplaceUnsignedAttributes(si, new BcCms.AttributeTable(unsignedAttrs));
            return (newsi, validationContext);
        }
    }
}
