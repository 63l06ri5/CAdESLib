using CAdESLib.Document.Validation;
using CAdESLib.Service;
using NLog;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Cms;
using System.Collections;
using System.Collections.Generic;
using BcCms = Org.BouncyCastle.Asn1.Cms;
namespace CAdESLib.Document.Signature.Extensions
{
    public class CAdESProfileT : CAdESSignatureExtension
    {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        /// <returns>
        /// the TSA used for the signature-time-stamp attribute
        /// </returns>
        public virtual ITspSource SignatureTsa { get; set; }

        public override SignatureProfile SignatureProfile => SignatureProfile.T;

        public CAdESProfileT(ITspSource signatureTsa)
        {
            this.SignatureTsa = signatureTsa;
        }

        protected internal override (SignerInformation, IValidationContext?) ExtendCMSSignature(CmsSignedData signedData, SignerInformation si, SignatureParameters parameters, IDocument originalData)
        {
            if (si is null)
            {
                throw new System.ArgumentNullException(nameof(si));
            }

            if (SignatureTsa == null)
            {
                throw new System.ArgumentNullException(nameof(SignatureTsa));
            }
            logger.Trace("Extend signature with id " + si.SignerID);
            BcCms.AttributeTable unsigned = si.UnsignedAttributes;
            IDictionary unsignedAttrHash;
            if (unsigned is null)
            {
                unsignedAttrHash = new Dictionary<DerObjectIdentifier, Attribute>();
            }
            else
            {
                unsignedAttrHash = si.UnsignedAttributes.ToDictionary();
            }

            //TODO: jbonilla - What happens if it is already CAdES-T? It should not be extended again.
            Attribute signatureTimeStamp = GetTimeStampAttribute(PkcsObjectIdentifiers.IdAASignatureTimeStampToken, SignatureTsa, si.GetSignature(), SignatureProfile != SignatureProfile.T);
            unsignedAttrHash.Add(PkcsObjectIdentifiers.IdAASignatureTimeStampToken, signatureTimeStamp);
            SignerInformation newsi = SignerInformation.ReplaceUnsignedAttributes(si, new BcCms.AttributeTable
                (unsignedAttrHash));
            return (newsi, null);
        }
    }
}
