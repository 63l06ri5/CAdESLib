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
using System.Linq;
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
        public override SignatureProfile SignatureProfile => SignatureProfile.XL;

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
            SetValues(
                unsignedAttrs,
                signingCertificate,
                validationContext.GetCertsChain(validationContext.NeededCertificates.First(x => x.Certificate.Equals(signingCertificate))),
                validationContext);

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
            DateTime? signingTime = signature.SigningTime?.Value ?? null;
            if (signingTime == null)
            {
                signingTime = parameters.SigningDate;
            }
            if (signingTime == null)
            {
                signingTime = DateTime.Now;
            }
            unsignedAttrs = ExtendUnsignedAttributes(unsignedAttrs, signature.SigningCertificate, signingTime.Value, signature.CertificateSource, validationContext);
            SignerInformation newsi = SignerInformation.ReplaceUnsignedAttributes(si, new BcCms.AttributeTable(unsignedAttrs));
            return (newsi, validationContext);
        }
    }
}
