using NLog;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using System.Collections;
using System.Collections.Generic;
using BcCms = Org.BouncyCastle.Asn1.Cms;
namespace CAdESLib.Document.Signature.Extensions
{
    public class CAdESProfileT : CAdESSignatureExtension
    {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        internal AlgorithmIdentifier digestAlgorithm = new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1);

        protected internal override SignerInformation ExtendCMSSignature(CmsSignedData signedData, SignerInformation si, SignatureParameters parameters, Document originalData)
        {
            if (si is null)
            {
                throw new System.ArgumentNullException(nameof(si));
            }

            if (SignatureTsa == null)
            {
                throw new System.ArgumentNullException(nameof(SignatureTsa));
            }
            logger.Info("Extend signature with id " + si.SignerID);
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
            Attribute signatureTimeStamp = GetTimeStampAttribute(PkcsObjectIdentifiers.IdAASignatureTimeStampToken, SignatureTsa, digestAlgorithm, si.GetSignature());
            unsignedAttrHash.Add(PkcsObjectIdentifiers.IdAASignatureTimeStampToken, signatureTimeStamp);
            SignerInformation newsi = SignerInformation.ReplaceUnsignedAttributes(si, new BcCms.AttributeTable
                (unsignedAttrHash));
            return newsi;
        }
    }
}
