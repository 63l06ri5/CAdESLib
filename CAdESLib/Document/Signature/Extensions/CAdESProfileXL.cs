using CAdESLib.Document.Validation;
using CAdESLib.Service;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.X509;
using System;
using System.Collections;
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

        public CAdESProfileXL(ITspSource signatureTsa, ICertificateVerifier certificateVerifier) : base(signatureTsa, certificateVerifier) { }

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

        protected internal override (SignerInformation, IValidationContext) ExtendCMSSignature(CmsSignedData signedData, SignerInformation si, SignatureParameters parameters, IDocument? originalData)
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
                signingTime = DateTime.Now.ToUniversalTime();
            }
            var signingCertificate = signature.SigningCertificate;
            if (signingCertificate is null)
            {
                throw new ArgumentNullException(nameof(signingCertificate));
            }

            unsignedAttrs = ExtendUnsignedAttributes(unsignedAttrs, signingCertificate, signingTime.Value.ToUniversalTime(), signature.CertificateSource, validationContext);
            SignerInformation newsi = SignerInformation.ReplaceUnsignedAttributes(si, new BcCms.AttributeTable(unsignedAttrs));
            return (newsi, validationContext);
        }
    }
}
