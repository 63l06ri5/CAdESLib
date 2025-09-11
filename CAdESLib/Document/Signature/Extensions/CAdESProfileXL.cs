using CAdESLib.Document.Validation;
using CAdESLib.Service;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.X509;
using System;
using System.Linq;
using CAdESLib.Helpers;
using Org.BouncyCastle.Tsp;
using NLog;
using PkcsObjectIdentifiers = Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers;

namespace CAdESLib.Document.Signature.Extensions
{
    /// <summary>
    /// This class holds the CAdES-X signature profiles; it supports the inclusion of a combination of the unsigned
    /// attributes id-aa-ets-escTimeStamp, id-aa-ets-certCRLTimestamp, id-aa-ets-certValues, id-aa-ets-revocationValues as
    /// defined in ETSI TS 101 733 V1.8.1, clause 6.3.
    /// </summary>

    public class CAdESProfileXL : CAdESProfileX
    {
        private static readonly Logger nloglogger = LogManager.GetCurrentClassLogger();

        public override SignatureProfile SignatureProfile => SignatureProfile.XL;

        public CAdESProfileXL(
                ITspSource signatureTsa,
                ICertificateVerifier certificateVerifier,
                ICryptographicProvider provider,
                ICurrentTimeGetter currentTimeGetter) : base(signatureTsa, certificateVerifier, provider, currentTimeGetter) { }

        /// <summary>
        /// Sets the type of the CAdES-X signature (Type 1 with id-aa-ets-escTimeStamp or Type 2 with
        /// id-aa-ets-certCRLTimestamp)
        /// </summary>
        /// <param>
        /// to type to set, 1 or 2, or 0 if it should be pure XL
        /// </param>
        public override void SetExtendedValidationType(int extendedValidationType)
        {
            this.extendedValidationType = extendedValidationType;
        }

        private OrderedAttributeTable ExtendUnsignedAttributes(
                OrderedAttributeTable unsignedAttrs,
                X509Certificate signingCertificate,
                DateTime signingDate,
                DateTime endDate,
                ICertificateSource optionalCertificateSource,
                IValidationContext validationContext,
                bool createNewAttributeIfExist)
        {
            var revocationInfo = validationContext.RevocationInfoDict[signingCertificate.GetHashCode()]!;
            var certChain = revocationInfo.GetCertsChain(
                signingCertificate,
                signingDate,
                endDate);
            SetValues(
                revocationInfo,
                signingDate,
                endDate,
                unsignedAttrs,
                signingCertificate,
                certChain,
                validationContext,
                createNewAttributeIfExist,
                !(unsignedAttrs[PkcsObjectIdentifiers.IdAAEtsEscTimeStamp]?.Any() ?? false));

            return unsignedAttrs;
        }

        protected internal override (SignerInfo, IValidationContext) ExtendCMSSignature(
                CmsSignedData signedData,
                DateTime endDate,
                SignerInformation signerInformation,
                SignatureParameters parameters,
                IDocument? originalData)
        {
            // TODO: apply attribute affinity rule and parameters.CreateNewAttributeIfExist
            if (parameters is null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }
                
            var (newSi, validationContext) = base.ExtendCMSSignature(signedData, endDate, signerInformation, parameters, originalData);
            var unsignedAttrs = new OrderedAttributeTable(newSi.UnauthenticatedAttributes);
            var tCms = new TimeStampToken(new CmsSignedData(
                    unsignedAttrs[Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.IdAASignatureTimeStampToken]!
                        .First().AttrValues[0].GetDerEncoded()));
            CAdESSignature signature = new CAdESSignature(signedData, signerInformation.SignerID);
            DateTime? signingTime = tCms?.TimeStampInfo.GenTime ?? signature.SigningTime?.Value;
            if (signingTime == null)
            {
                signingTime = parameters.SigningDate;
            }
            if (signingTime == null)
            {
                signingTime = this.CurrentTimeGetter.CurrentUtcTime;
            }
            var signingCertificate = signature.SigningCertificate;
            if (signingCertificate is null)
            {
                throw new ArgumentNullException(nameof(signingCertificate));
            }

            unsignedAttrs = ExtendUnsignedAttributes(
                    unsignedAttrs,
                    signingCertificate,
                    signingTime.Value.ToUniversalTime(),
                    endDate,
                    signature.CertificateSource,
                    validationContext,
                    parameters.CreateNewAttributeIfExist);
            newSi = ReplaceUnsignedAttributes(newSi, unsignedAttrs);
            return (newSi, validationContext);
        }
    }
}
