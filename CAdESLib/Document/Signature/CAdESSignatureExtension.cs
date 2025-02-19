using CAdESLib.Document.Validation;
using CAdESLib.Helpers;
using CAdESLib.Service;
using NLog;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using BcCms = Org.BouncyCastle.Asn1.Cms;

namespace CAdESLib.Document.Signature.Extensions
{
    public abstract class CAdESSignatureExtension : ISignatureExtension
    {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        private const string CannotParseCMSDataMessage = "Cannot parse CMS data";
        private const string EmptyTimestampMessage = "The TimeStampToken returned for the signature time stamp was empty.";

        public virtual SignatureProfile SignatureProfile => throw new NotImplementedException();

        public virtual (IDocument, ICollection<IValidationContext?>?) ExtendSignatures(
            IDocument document,
            IDocument? originalData,
            SignatureParameters parameters)
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
                var validationContexts = new List<IValidationContext?>();

                foreach (var si in signerStore.GetSigners().Cast<SignerInformation>())
                {
                    try
                    {
                        // Hack to avoid mistakes when a signature has already been extended.
                        // It is assumed that only signatures are extended from BES.
                        // TODO It should be validated to what extent it was extended (BES, T, C, X, XL).
                        if (si.UnsignedAttributes == null || si.UnsignedAttributes.Count == 0)
                        {
                            var (signerInformation, validationContext) = ExtendCMSSignature(signedData, si, parameters, originalData);
                            siArray.Add(signerInformation);
                            validationContexts.Add(validationContext);
                        }
                        else
                        {
                            //parameters.ValidationResult.Add(ValidationKey.Unknown, ValidationResultType.Warning, AlreadyExtendedMessage);
                            siArray.Add(si);
                        }
                    }
                    catch
                    {
                        //parameters.ValidationResult.Add(ValidationKey.Unknown, ValidationResultType.Warning, ExtendingSignatureExceptionMessage);
                        siArray.Add(si);
                    }
                }

                SignerInformationStore newSignerStore = new SignerInformationStore(siArray);
                CmsSignedData extended = CmsSignedData.ReplaceSigners(signedData, newSignerStore);
                return (new InMemoryDocument(extended.GetEncoded()), validationContexts);
            }
            catch (CmsException)
            {
                throw new IOException(CannotParseCMSDataMessage);
            }
        }

        protected internal abstract (SignerInformation, IValidationContext?) ExtendCMSSignature(CmsSignedData signedData, SignerInformation si, SignatureParameters parameters, IDocument? originalData);

        /// <summary>
        /// Computes an attribute containing a time-stamp token of the provided data, from the provided TSA using the
        /// provided.
        /// </summary>
        /// <remarks>
        /// Computes an attribute containing a time-stamp token of the provided data, from the provided TSA using the
        /// provided. The hashing is performed by the method using the specified algorithm and a BouncyCastle provider.
        /// </remarks>
        protected internal virtual BcCms.Attribute GetTimeStampAttribute(DerObjectIdentifier oid, ITspSource tsa, byte[] messageImprint, bool needToWaitTsTime = false)
        {
            if (tsa is null)
            {
                throw new ArgumentNullException(nameof(tsa));
            }

            IDigest? digest;
            string? algorithmOid;
            if (tsa is ITSAClient)
            {
                digest = tsa.GetMessageDigest();
                if (digest is null)
                {
                    throw new ArgumentNullException(nameof(digest));
                }

                algorithmOid = tsa.TsaDigestAlgorithmOID;
                if (algorithmOid is null)
                {
                    throw new ArgumentNullException(nameof(algorithmOid));
                }
            }
            else
            {
                digest = DigestUtilities.GetDigest(DigestAlgorithm.SHA1.Name);
                algorithmOid = DigestAlgorithm.SHA1.OID;
            }
            byte[] toTimeStamp = DigestAlgorithms.Digest(digest, messageImprint);

            var tsresp = tsa.GetTimeStampResponse(algorithmOid, toTimeStamp);
            var tstoken = tsresp?.TimeStampToken;
            if (tstoken == null)
            {
                throw new ArgumentNullException(EmptyTimestampMessage);
            }
            if (needToWaitTsTime)
            {
                // TODO: Think about it
                var utcNow = DateTime.UtcNow;
                var genTime = tstoken.TimeStampInfo.GenTime.ToUniversalTime();
                var datediff = genTime.Subtract(utcNow);
                if (datediff.TotalMilliseconds > 0)
                {
                    if (datediff.TotalMilliseconds < 60000)
                    {
                        Thread.Sleep((int)Math.Ceiling(datediff.TotalMilliseconds));
                    }
                    else
                    {
                        var message = $"Timestamp date is far in the future. GenTime = {genTime}, CheckTime = {utcNow} ";
                        logger.Error(message);
                        throw new Exception(message);
                    }
                }
            }

            BcCms.Attribute signatureTimeStamp = new BcCms.Attribute(oid, new DerSet(Asn1Object.FromByteArray(tstoken.GetEncoded())));
            return signatureTimeStamp;

        }
    }
}
