using CAdESLib.Document.Validation;
using CAdESLib.Service;
using CAdESLib.Helpers;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Cms;
using PkcsObjectIdentifiers = Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers;
using System.IO;
using System;
using Org.BouncyCastle.Asn1.Cms;
using System.Linq;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using Org.BouncyCastle.Tsp;
using NLog;

namespace CAdESLib.Document.Signature.Extensions
{
    /// <summary>
    /// This class holds the CAdES-X signature profiles; it supports the inclusion of a combination of the unsigned
    /// attributes id-aa-ets-escTimeStamp, id-aa-ets-certCRLTimestamp, id-aa-ets-certValues, id-aa-ets-revocationValues as
    /// defined in ETSI TS 101 733 V1.8.1, clause 6.3.
    /// </summary>
    public class CAdESProfileX : CAdESProfileC
    {
        private static readonly Logger nloglogger = LogManager.GetCurrentClassLogger();

        protected int extendedValidationType = 1;

        public override SignatureProfile SignatureProfile => SignatureProfile.XType1;

        public CAdESProfileX(
                ITspSource signatureTsa,
                ICertificateVerifier certificateVerifier,
                ICryptographicProvider provider,
                ICurrentTimeGetter currentTimeGetter) : base(signatureTsa, certificateVerifier, provider, currentTimeGetter) { }

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

        protected internal override (SignerInfo, IValidationContext) ExtendCMSSignature(
                CmsSignedData signedData,
                DateTime endDate,
                SignerInformation signerInformation,
                SignatureParameters parameters,
                IDocument? originalData)
        {
            // TODO: apply attribute affinity rule and parameters.CreateNewAttributeIfExist
            var levelXTime =
                    signerInformation.GetTimestampsX1()?.Select(x => x.GetGenTimeDate() as DateTime?).OrderBy(x => x).FirstOrDefault() ??
                    signerInformation.GetTimestampsX2()?.Select(x => x.GetGenTimeDate() as DateTime?).OrderBy(x => x).FirstOrDefault();

            var (si, validationContext) = base.ExtendCMSSignature(signedData, levelXTime ?? endDate, signerInformation, parameters, originalData);
            var unsignedAttributesTable = new OrderedAttributeTable(si.UnauthenticatedAttributes);
            DerObjectIdentifier attributeId;
            var signature = new CAdESSignature(signedData, signerInformation.SignerID);

            switch (GetExtendedValidationType())
            {
                case 1:
                    {
                        var timestamps = unsignedAttributesTable[PkcsObjectIdentifiers.IdAASignatureTimeStampToken]!.ToList();
                        foreach (var timestamp in timestamps)
                        {
                            using var toTimestamp = new MemoryStream();
                            attributeId = PkcsObjectIdentifiers.IdAAEtsEscTimeStamp;
                            Attribute? extendedTimeStamp = null;
                            var isNewAttribute = unsignedAttributesTable[attributeId] is var existedAttrs && (existedAttrs is null || existedAttrs.Count == 0)
                                    || parameters.CreateNewAttributeIfExist;
                            if (isNewAttribute)
                            {
                                toTimestamp.Write(si.EncryptedDigest.GetOctets());
                                toTimestamp.Write(timestamp.AttrType.GetDerEncoded());
                                toTimestamp.Write(timestamp.AttrValues.GetDerEncoded());
                                if (unsignedAttributesTable[PkcsObjectIdentifiers.IdAAEtsCertificateRefs]?.FirstOrDefault() is Attribute certRefsAttr)
                                {
                                    toTimestamp.Write(certRefsAttr.AttrType.GetDerEncoded());
                                    toTimestamp.Write(certRefsAttr.AttrValues.GetDerEncoded());
                                }

                                if (unsignedAttributesTable[PkcsObjectIdentifiers.IdAAEtsRevocationRefs]?.FirstOrDefault() is Attribute revsRefsAttr)
                                {
                                    toTimestamp.Write(revsRefsAttr.AttrType.GetDerEncoded());
                                    toTimestamp.Write(revsRefsAttr.AttrValues.GetDerEncoded());
                                }

                                extendedTimeStamp = GetTimeStampAttribute(attributeId, SignatureTsa, toTimestamp.ToArray());
                            }
                            else
                            {
                                extendedTimeStamp = existedAttrs!.First();
                            }

                            var tstSignedData = new CmsSignedData(extendedTimeStamp!.AttrValues[0].GetDerEncoded());
                            if (parameters.EnrichXTimestamp)
                            {
                                var tst = new TimeStampToken(tstSignedData);
                                tstSignedData = EnrichTimestampsWithRefsAndValues(
                                        tstSignedData,
                                        endDate,
                                        validationContext,
                                        signature.CertificateSource,
                                        signature.CRLSource,
                                        signature.OCSPSource,
                                        parameters.DigestAlgorithmOID,
                                        parameters.CreateNewAttributeIfExist,
                                        !(unsignedAttributesTable[CAdESProfileA.id_aa_ets_archiveTimestamp_v3]?.Any() ?? false)
                                        );
                            }

                            var derSet = new DerSet(Asn1Object.FromByteArray(tstSignedData.GetEncoded("DER")));
                            var enrichedAttribute = new Attribute(
                                    attributeId,
                                    derSet);

                            if (isNewAttribute)
                            {
                                unsignedAttributesTable.AddAttribute(enrichedAttribute);
                            }
                            else
                            {
                                unsignedAttributesTable.ReplaceAttribute(extendedTimeStamp, derSet);
                            }
                        }
                        break;
                    }

                case 2:
                    {
                        attributeId = PkcsObjectIdentifiers.IdAAEtsCertCrlTimestamp;
                        Attribute? extendedTimeStamp = null;
                        var isNewAttribute = unsignedAttributesTable[attributeId] is var existedAttrs && (existedAttrs is null || existedAttrs.Count == 0)
                                || parameters.CreateNewAttributeIfExist;
                        if (isNewAttribute)
                        {
                            using var toTimestamp = new MemoryStream();
                            if (unsignedAttributesTable[PkcsObjectIdentifiers.IdAAEtsCertificateRefs]?.FirstOrDefault() is Attribute certRefsAttr)
                            {
                                toTimestamp.Write(certRefsAttr.AttrType.GetDerEncoded());
                                toTimestamp.Write(certRefsAttr.AttrValues.GetDerEncoded());
                            }

                            if (unsignedAttributesTable[PkcsObjectIdentifiers.IdAAEtsRevocationRefs]?.FirstOrDefault() is Attribute revsRefsAttr)
                            {
                                toTimestamp.Write(revsRefsAttr.AttrType.GetDerEncoded());
                                toTimestamp.Write(revsRefsAttr.AttrValues.GetDerEncoded());
                            }

                            extendedTimeStamp = GetTimeStampAttribute(attributeId, SignatureTsa, toTimestamp.ToArray());
                        }
                        else
                        {
                            extendedTimeStamp = existedAttrs!.First();
                        }

                        var tstSignedData = new CmsSignedData(extendedTimeStamp!.AttrValues[0].GetDerEncoded());
                        if (parameters.EnrichXTimestamp)
                        {
                            var tst = new TimeStampToken(tstSignedData);
                            tstSignedData = EnrichTimestampsWithRefsAndValues(
                                    tstSignedData,
                                    endDate,
                                    validationContext,
                                    signature.CertificateSource,
                                    signature.CRLSource,
                                    signature.OCSPSource,
                                    parameters.DigestAlgorithmOID,
                                    parameters.CreateNewAttributeIfExist,
                                    !(unsignedAttributesTable[CAdESProfileA.id_aa_ets_archiveTimestamp_v3]?.Any() ?? false)
                                    );
                        }
                        var derSet = new DerSet(Asn1Object.FromByteArray(tstSignedData.GetEncoded("DER")));
                        var enrichedAttribute = new Attribute(
                                attributeId,
                                derSet);

                        if (isNewAttribute)
                        {
                            unsignedAttributesTable.AddAttribute(enrichedAttribute);
                        }
                        else
                        {
                            unsignedAttributesTable.ReplaceAttribute(extendedTimeStamp, derSet);
                        }
                        break;
                    }

                default:
                    {
                        return (si, validationContext);
                    }
            }

            return (ReplaceUnsignedAttributes(si, unsignedAttributesTable), validationContext);
        }
    }
}
