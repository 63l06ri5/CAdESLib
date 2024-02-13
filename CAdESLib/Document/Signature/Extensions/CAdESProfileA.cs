using CAdESLib.Document.Validation;
using CAdESLib.Service;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Cms;
using System.Collections;

namespace CAdESLib.Document.Signature.Extensions
{
    /// <summary>
    /// This class holds the CAdES-A signature profiles; it supports the later, over time _extension_ of a signature with
    /// id-aa-ets-archiveTimestampV2 attributes as defined in ETSI TS 101 733 V1.8.1, clause 6.4.1.
    /// </summary>
    /// <remarks>
    /// This class holds the CAdES-A signature profiles; it supports the later, over time _extension_ of a signature with
    /// id-aa-ets-archiveTimestampV2 attributes as defined in ETSI TS 101 733 V1.8.1, clause 6.4.1.
    /// "If the certificate-values and revocation-values attributes are not present in the CAdES-BES or CAdES-EPES, then they
    /// shall be added to the electronic signature prior to computing the archive time-stamp token." is the reason we extend
    /// from the XL profile.
    /// </remarks>
    public class CAdESProfileA : CAdESProfileXL
    {
        public static readonly DerObjectIdentifier id_aa_ets_archiveTimestamp = PkcsObjectIdentifiers.IdAAEtsArchiveTimestamp;

        public override SignatureProfile SignatureProfile => SignatureProfile.A;

        public CAdESProfileA(ITspSource signatureTsa, ICertificateVerifier certificateVerifier) : base(signatureTsa, certificateVerifier) { }

        protected internal override (SignerInformation, IValidationContext) ExtendCMSSignature(CmsSignedData cmsSignedData, SignerInformation si, SignatureParameters parameters, IDocument originalDocument)
        {
            var (newSi, validationContext) = base.ExtendCMSSignature(cmsSignedData, si, parameters, originalDocument);
            si = newSi;
            CAdESSignature signature = new CAdESSignature(cmsSignedData, si);
            IDictionary unsignedAttrHash = si.UnsignedAttributes.ToDictionary();
            Attribute archiveTimeStamp = GetTimeStampAttribute(CAdESProfileA.id_aa_ets_archiveTimestamp, SignatureTsa, signature.GetArchiveTimestampData(0, originalDocument));
            unsignedAttrHash.Add(id_aa_ets_archiveTimestamp, archiveTimeStamp);
            SignerInformation newsi = SignerInformation.ReplaceUnsignedAttributes(si, new AttributeTable
                (unsignedAttrHash));
            return (newsi, validationContext);
        }
    }
}
