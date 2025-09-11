using CAdESLib.Document.Validation;
using CAdESLib.Helpers;
using CAdESLib.Service;
using NLog;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Cms;
using PkcsObjectIdentifiers = Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers;
using System;

namespace CAdESLib.Document.Signature.Extensions
{
    public class CAdESProfileT : CAdESSignatureExtension
    {
        private static readonly Logger nloglogger = LogManager.GetCurrentClassLogger();

        /// <returns>
        /// the TSA used for the signature-time-stamp attribute
        /// </returns>
        public virtual ITspSource SignatureTsa { get; set; }

        public override SignatureProfile SignatureProfile => SignatureProfile.T;

        public CAdESProfileT(
                ITspSource signatureTsa,
                ICryptographicProvider cryptographicProvider,
                ICurrentTimeGetter currentTimeGetter): base(cryptographicProvider, currentTimeGetter)
        {
            this.SignatureTsa = signatureTsa;
        }

        protected internal override (SignerInfo, IValidationContext?) ExtendCMSSignature(
                CmsSignedData signedData,
                DateTime endDate,
                SignerInformation si,
                SignatureParameters parameters,
                IDocument? originalData)
        {
            if (si is null)
            {
                throw new System.ArgumentNullException(nameof(si));
            }

            if (SignatureTsa == null)
            {
                throw new System.ArgumentNullException(nameof(SignatureTsa));
            }

            var unsignedAttrTable = new OrderedAttributeTable(si.ToSignerInfo().UnauthenticatedAttributes);
            if (unsignedAttrTable[PkcsObjectIdentifiers.IdAASignatureTimeStampToken] != null
                    && unsignedAttrTable[PkcsObjectIdentifiers.IdAASignatureTimeStampToken]!.Count != 0
                    && !parameters.CreateNewAttributeIfExist)
            {
                nloglogger.Trace("Already had a signature-time-stamp and parameters says to not create a new one");
                return (si.ToSignerInfo(), null);
            }

            var signatureTimeStamp = GetTimeStampAttribute(
                    PkcsObjectIdentifiers.IdAASignatureTimeStampToken,
                    SignatureTsa,
                    si.GetSignature(),
                    SignatureProfile != SignatureProfile.T);
            unsignedAttrTable.AddAttribute(signatureTimeStamp);
            var newsi = ReplaceUnsignedAttributes(si, unsignedAttrTable);
            return (newsi, null);
        }
    }
}
