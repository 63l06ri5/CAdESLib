using System;
using System.Collections.Generic;
using System.IO;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;
using CAdESLib.Helpers;
using CAdESLib.Service;
using BcCms = Org.BouncyCastle.Asn1.Cms;

namespace CAdESLib.Document.Signature.Extensions
{
    public abstract class CAdESSignatureExtension : ISignatureExtension
    {
        private const string AlreadyExtendedMessage = "Already extended?";
        private const string ExtendingSignatureExceptionMessage = "Exception when extending signature";
        private const string CannotParseCMSDataMessage = "Cannot parse CMS data";
        private const string EmptyTimestampMessage = "The TimeStampToken returned for the signature time stamp was empty.";
        private ITspSource signatureTsa;

        /// <returns>
        /// the TSA used for the signature-time-stamp attribute
        /// </returns>
        public virtual ITspSource SignatureTsa { get => signatureTsa; set => signatureTsa = value; }

        public virtual Document ExtendSignatures(Document document, Document originalData, SignatureParameters parameters)
        {
            if (document is null)
            {
                throw new ArgumentNullException(nameof(document));
            }

            try
            {
                CmsSignedData signedData = new CmsSignedData(document.OpenStream());
                SignerInformationStore signerStore = signedData.GetSignerInfos();
                var siArray = new List<SignerInformation>();

                foreach (SignerInformation si in signerStore.GetSigners())
                {
                    try
                    {
                        // jbonilla - Hack to avoid mistakes when a signature has already been extended.
                        // It is assumed that only signatures are extended from BES.
                        // TODO jbonilla - It should be validated to what extent it was extended (BES, T, C, X, XL).
                        if (si.UnsignedAttributes == null || si.UnsignedAttributes.Count == 0)
                        {
                            siArray.Add(ExtendCMSSignature(signedData, si, parameters, originalData));
                        }
                        else
                        {
                            //parameters.ValidationResult.Add(ValidationKey.Unknown, ValidationResultType.Warning, AlreadyExtendedMessage);
                            siArray.Add(si);
                        }
                    }
                    catch (IOException)
                    {
                        //parameters.ValidationResult.Add(ValidationKey.Unknown, ValidationResultType.Warning, ExtendingSignatureExceptionMessage);
                        siArray.Add(si);
                    }
                }

                SignerInformationStore newSignerStore = new SignerInformationStore(siArray);
                CmsSignedData extended = CmsSignedData.ReplaceSigners(signedData, newSignerStore);
                return new InMemoryDocument(extended.GetEncoded());
            }
            catch (CmsException)
            {
                throw new IOException(CannotParseCMSDataMessage);
            }
        }

        protected internal abstract SignerInformation ExtendCMSSignature(CmsSignedData signedData, SignerInformation si, SignatureParameters parameters, Document originalData);

        /// <summary>
        /// Computes an attribute containing a time-stamp token of the provided data, from the provided TSA using the
        /// provided.
        /// </summary>
        /// <remarks>
        /// Computes an attribute containing a time-stamp token of the provided data, from the provided TSA using the
        /// provided. The hashing is performed by the method using the specified algorithm and a BouncyCastle provider.
        /// </remarks>
        protected internal virtual BcCms.Attribute GetTimeStampAttribute(DerObjectIdentifier oid, ITspSource tsa, byte[] messageImprint)
        {
            if (tsa is null)
            {
                throw new ArgumentNullException(nameof(tsa));
            }

            IDigest digest;
            string algorithmOid;
            if (tsa is ITSAClient)
            {
                digest = tsa.GetMessageDigest();
                algorithmOid = tsa.TsaDigestAlgorithmOID;
            }
            else
            {
                digest = DigestUtilities.GetDigest(DigestAlgorithm.SHA1.Name);
                algorithmOid = DigestAlgorithm.SHA1.OID;
            }
            byte[] toTimeStamp = DigestAlgorithms.Digest(digest, messageImprint);

            TimeStampResponse tsresp = tsa.GetTimeStampResponse(algorithmOid, toTimeStamp);
            TimeStampToken tstoken = tsresp.TimeStampToken;
            if (tstoken == null)
            {
                throw new ArgumentNullException(EmptyTimestampMessage);
            }
            BcCms.Attribute signatureTimeStamp = new BcCms.Attribute(oid, new DerSet(Asn1Object.FromByteArray(tstoken.GetEncoded())));
            return signatureTimeStamp;

        }
    }
}
