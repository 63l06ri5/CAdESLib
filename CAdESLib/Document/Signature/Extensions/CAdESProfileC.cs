using CAdESLib.Document.Validation;
using CAdESLib.Helpers;
using CAdESLib.Service;
using NLog;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;
using PkcsObjectIdentifiers = Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers;
using System.Linq;
using System;

namespace CAdESLib.Document.Signature.Extensions
{
    /// <summary>
    /// This class holds the CAdES-C signature profile; it supports the inclusion of the mandatory unsigned
    /// id-aa-ets-certificateRefs and id-aa-ets-revocationRefs attributes as specified in ETSI TS 101 733 V1.8.1, clauses
    /// 6.2.1 & 6.2.2.
    /// </summary>

    public class CAdESProfileC : CAdESProfileT
    {
        private static readonly Logger nloglogger = LogManager.GetCurrentClassLogger();

        public ICertificateVerifier CertificateVerifier { get; set; }

        public override SignatureProfile SignatureProfile => SignatureProfile.C;

        public CAdESProfileC(
                ITspSource signatureTsa,
                ICertificateVerifier certificateVerifier,
                ICryptographicProvider cryptographicProvider,
                ICurrentTimeGetter currentTimeGetter) : base(signatureTsa, cryptographicProvider, currentTimeGetter)
        {
            this.CertificateVerifier = certificateVerifier;
        }

        private (OrderedAttributeTable, IValidationContext) ExtendUnsignedAttributes(
            CmsSignedData cms,
            OrderedAttributeTable unsignedAttrs,
            X509Certificate signingCertificate,
            SignatureParameters parameters,
            DateTime signingTime,
            DateTime endDate,
            ICertificateSource optionalCertificateSource,
            ICrlSource optionalCrlSource,
            IOcspSource optionalOcspSource,
            IValidationContext? validationContext)
        {
            validationContext = validationContext ?? CertificateVerifier.GetValidationContext(signingCertificate);
            var timeStampAttrs = unsignedAttrs[PkcsObjectIdentifiers.IdAASignatureTimeStampToken];
            if (timeStampAttrs != null)
            {
                foreach (var timeStampAttr in timeStampAttrs)
                {
                    var tstSignedData = new CmsSignedData(timeStampAttr.AttrValues[0].GetDerEncoded());
                    var newTstSignedData = EnrichTimestampsWithRefsAndValues(
                            tstSignedData,
                            endDate,
                            validationContext,
                            optionalCertificateSource,
                            optionalCrlSource,
                            optionalOcspSource,
                            parameters.DigestAlgorithmOID,
                            parameters.CreateNewAttributeIfExist,
                            !(unsignedAttrs[PkcsObjectIdentifiers.IdAAEtsEscTimeStamp]?.Any() ?? false)
                            );
                    unsignedAttrs.ReplaceAttribute(
                            timeStampAttr,
                            new DerSet(Asn1Object.FromByteArray(newTstSignedData.GetEncoded("DER"))));
                }
            }
            else
            {
                throw new ArgumentNullException("There is no timestamp");
            }

            validationContext.ValidateCertificate(
                cms,
                signingCertificate,
                signingTime,
                endDate,
                new CompositeCertificateSource(parameters.CertificateChain is null ?
                    null : new ListCertificateSource(parameters.CertificateChain), optionalCertificateSource),
                optionalCrlSource,
                optionalOcspSource);

            var revocationInfo = validationContext.RevocationInfoDict[signingCertificate.GetHashCode()]!;

            nloglogger.Trace("Refs for main");
            if (nloglogger.IsTraceEnabled)
            {
                foreach (var nct in revocationInfo.NeededCertificateTokens)
                {
                    nloglogger.Trace(
                            $"root cause: {string.Join(", ", nct.RootCause.Where(x => !(x is null)).Select(x => x!.GetType().ToString()))}, cert: {nct.Certificate.ToFineString()}");
                }
            }

            SetRefs(
                this.CryptographicProvider,
                revocationInfo,
                signingTime,
                endDate,
                parameters.DigestAlgorithmOID,
                unsignedAttrs,
                signingCertificate,
                revocationInfo.GetCertsChain(
                    signingCertificate,
                    signingTime,
                    endDate),
                validationContext,
                parameters.CreateNewAttributeIfExist,
                !(unsignedAttrs[PkcsObjectIdentifiers.IdAAEtsEscTimeStamp]?.Any() ?? false)
                );

            return (unsignedAttrs, validationContext);
        }


        protected internal override (SignerInfo, IValidationContext) ExtendCMSSignature(
                CmsSignedData signedData,
                DateTime endDate,
                SignerInformation si,
                SignatureParameters parameters,
                IDocument? originalData)
        {
            // TODO: apply attribute affinity rule and parameters.CreateNewAttributeIfExist
            if (si is null)
            {
                throw new ArgumentNullException(nameof(si));
            }

            if (parameters is null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            var (newSi, validationContext) = base.ExtendCMSSignature(signedData, endDate, si, parameters, originalData);
            var unsignedAttrs = new OrderedAttributeTable(newSi.UnauthenticatedAttributes);

            var tCms = new TimeStampToken(new CmsSignedData(
                    unsignedAttrs[PkcsObjectIdentifiers.IdAASignatureTimeStampToken]!
                        .First().AttrValues[0].GetDerEncoded()));

            var signature = new CAdESSignature(signedData, si.SignerID);
            var signingCertificate = signature.SigningCertificate;
            if (signingCertificate is null)
            {
                throw new ArgumentNullException(nameof(signingCertificate));
            }

            (unsignedAttrs, validationContext) = ExtendUnsignedAttributes(
                signedData,
                unsignedAttrs,
                signingCertificate,
                parameters,
                tCms?.TimeStampInfo.GenTime ?? (signature.SigningTime?.Value ?? this.CurrentTimeGetter.CurrentUtcTime).ToUniversalTime(),
                endDate,
                signature.CertificateSource,
                signature.CRLSource,
                signature.OCSPSource,
                validationContext);
            return (ReplaceUnsignedAttributes(newSi, unsignedAttrs), validationContext);
        }
    }
}
