﻿using CAdESLib.Document.Validation;
using CAdESLib.Service;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Cms;
using System;
using System.IO;
using BcCms = Org.BouncyCastle.Asn1.Cms;

namespace CAdESLib.Document.Signature.Extensions
{
    /// <summary>
    /// This class holds the CAdES-X signature profiles; it supports the inclusion of a combination of the unsigned
    /// attributes id-aa-ets-escTimeStamp, id-aa-ets-certCRLTimestamp, id-aa-ets-certValues, id-aa-ets-revocationValues as
    /// defined in ETSI TS 101 733 V1.8.1, clause 6.3.
    /// </summary>
    public class CAdESProfileX : CAdESProfileC
    {
        protected int extendedValidationType = 1;

        public override SignatureProfile SignatureProfile => SignatureProfile.XType1;

        public CAdESProfileX(ITspSource signatureTsa, ICertificateVerifier certificateVerifier) : base(signatureTsa, certificateVerifier) { }

        /// <summary>
        /// Gets the type of the CAdES-X signature (Type 1 with id-aa-ets-escTimeStamp or Type 2 with
        /// id-aa-ets-certCRLTimestamp)
        /// </summary>
        /// <returns>
        /// the extendedValidationType
        /// </returns>
        public virtual int GetExtendedValidationType()
        {
            return extendedValidationType;
        }

        /// <summary>
        /// Sets the type of the CAdES-X signature (Type 1 with id-aa-ets-escTimeStamp or Type 2 with
        /// id-aa-ets-certCRLTimestamp)
        /// </summary>
        /// <param>
        /// to type to set, 1 or 2
        /// </param>
        public virtual void SetExtendedValidationType(int extendedValidationType)
        {
            if (extendedValidationType != 1 && extendedValidationType != 2)
            {
                throw new ArgumentException("The extended validation data type (CAdES-X type) shall be either 1 or 2");
            }
            this.extendedValidationType = extendedValidationType;
        }

        protected internal override (SignerInformation, IValidationContext) ExtendCMSSignature(CmsSignedData signedData, SignerInformation si, SignatureParameters parameters, IDocument originalData)
        {
            var (newSi, validationContext) = base.ExtendCMSSignature(signedData, si, parameters, originalData);
            si = newSi;
            using var toTimestamp = new MemoryStream();
            DerObjectIdentifier attributeId;
            switch (GetExtendedValidationType())
            {
                case 1:
                    {
                        attributeId = PkcsObjectIdentifiers.IdAAEtsEscTimeStamp;
                        toTimestamp.Write(si.GetSignature());
                        // We don't include the outer SEQUENCE, only the attrType and attrValues as stated by the TS Â§6.3.5,
                        // NOTE 2)
                        toTimestamp.Write(si.UnsignedAttributes[PkcsObjectIdentifiers.IdAASignatureTimeStampToken].AttrType.GetDerEncoded());
                        toTimestamp.Write(si.UnsignedAttributes[PkcsObjectIdentifiers.IdAASignatureTimeStampToken].AttrValues.GetDerEncoded());
                        break;
                    }

                case 2:
                    {
                        attributeId = PkcsObjectIdentifiers.IdAAEtsCertCrlTimestamp;
                        break;
                    }

                default:
                    {
                        return (si, validationContext);
                    }
            }
            var unsignedAttributes = si.UnsignedAttributes.ToDictionary();

            if (unsignedAttributes.Contains(PkcsObjectIdentifiers.IdAAEtsCertificateRefs) && unsignedAttributes[PkcsObjectIdentifiers.IdAAEtsCertificateRefs] != null)
            {
                toTimestamp.Write(si.UnsignedAttributes[PkcsObjectIdentifiers.IdAAEtsCertificateRefs].AttrType.GetDerEncoded());
                toTimestamp.Write(si.UnsignedAttributes[PkcsObjectIdentifiers.IdAAEtsCertificateRefs].AttrValues.GetDerEncoded());
            }

            if (unsignedAttributes.Contains(PkcsObjectIdentifiers.IdAAEtsRevocationRefs) && unsignedAttributes[PkcsObjectIdentifiers.IdAAEtsRevocationRefs] != null)
            {
                toTimestamp.Write(si.UnsignedAttributes[PkcsObjectIdentifiers.IdAAEtsRevocationRefs].AttrType.GetDerEncoded());
                toTimestamp.Write(si.UnsignedAttributes[PkcsObjectIdentifiers.IdAAEtsRevocationRefs].AttrValues.GetDerEncoded());
            }

            BcCms.Attribute extendedTimeStamp = GetTimeStampAttribute(attributeId, SignatureTsa, toTimestamp.ToArray());
            unsignedAttributes.Add(attributeId, extendedTimeStamp);
            return (SignerInformation.ReplaceUnsignedAttributes(si, new BcCms.AttributeTable(unsignedAttributes)), validationContext);
        }
    }
}
