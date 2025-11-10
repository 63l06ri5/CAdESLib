using CAdESLib.Document.Signature;
using CAdESLib.Helpers;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using NLog;
using CAdESLib.Document.Signature.Extensions;

namespace CAdESLib.Document.Validation
{
    using ResultStatus = SignatureValidationResult.ResultStatus;

    public interface ISignedDocumentValidator
    {
        /// <summary>
        /// Validate the document and all its signatures
        /// </summary>
        /// <returns>
        /// the validation report
        /// </returns>
        ValidationReport ValidateDocument(
                IDocument document,
                bool checkIntegrity = true,
                IDocument? externalContent = null,
                ICollection<IValidationContext?>? validationContexts = null,
                RuntimeValidatingParams? runtimeValidatingParams = null);

        /// <summary>
        /// Validate the document and all its signatures
        /// </summary>
        /// <returns>
        /// the validation report and collection of context
        /// </returns>
        (ValidationReport, ICollection<IValidationContext?>) ValidateDocumentWithContext(
                IDocument document,
                bool checkIntegrity = true,
                IDocument? externalContent = null,
                ICollection<IValidationContext?>? validationContexts = null,
                RuntimeValidatingParams? runtimeValidatingParams = null);
    }

    /// <summary>
    /// Validate the signed document
    /// </summary>
    public class SignedDocumentValidator : ISignedDocumentValidator
    {
        private static readonly Logger nloglogger = LogManager.GetCurrentClassLogger();
        private readonly Func<ICAdESLogger> loggerFactory;
        private readonly Func<X509Certificate, ICAdESLogger, IValidationContext> validationContextFactory;
        private ICurrentTimeGetter CurrentTimeGetter { get; }

        /// <param>
        /// the certificateVerifier to set
        /// </param>
        public ICertificateVerifier CertificateVerifier { get; private set; }

        private readonly ICryptographicProvider cryptographicProvider;

        public SignedDocumentValidator(
                ICertificateVerifier certificateVerifier,
                Func<ICAdESLogger> loggerFactory,
                Func<X509Certificate,
                    ICAdESLogger,
                    IValidationContext> validationContextFactory,
                ICryptographicProvider cryptographicProvider,
                ICurrentTimeGetter currentTimeGetter)
        {
            CertificateVerifier = certificateVerifier;
            this.loggerFactory = loggerFactory;
            this.validationContextFactory = validationContextFactory;
            this.cryptographicProvider = cryptographicProvider;
            this.CurrentTimeGetter = currentTimeGetter;
        }

        /// <summary>
        /// Guess the document format and return an appropriate document
        /// </summary>
        /// <param name="document"></param>
        /// <returns></returns>
        public static CmsSignedData GetCmsSignedData(IDocument document)
        {
            if (document is null)
            {
                throw new ArgumentNullException(nameof(document));
            }

            using var input = document.OpenStream();
            byte[] preamble = new byte[5];
            int read = input.Read(preamble, 0, 5);

            if (read < 5)
            {
                throw new ArgumentException("Not a signed document");
            }

            if (preamble[0] == unchecked(0x30))
            {
                try
                {
                    return new CmsSignedData(document.OpenStream());
                }
                catch (CmsException)
                {
                    throw new IOException("Not a valid CAdES file");
                }
            }
            else
            {
                throw new ArgumentException("Document format not recognized/handled");
            }
        }

        /// <summary>
        /// Retrieves the signatures found in the document
        /// </summary>
        /// <returns>
        /// a list of IAdvancedSignatures for validation purposes
        /// </returns>
        public static IList<IAdvancedSignature> GetSignatures(CmsSignedData cmsSignedData)
        {
            var signatures = new List<IAdvancedSignature>();
            foreach (var o in cmsSignedData.GetSignerInfos().GetSigners().Cast<SignerInformation>())
            {
                CAdESSignature info = new CAdESSignature(cmsSignedData, o);
                signatures.Add(info);
            }
            return signatures;
        }

        protected internal virtual SignatureVerification[]? VerifyCounterSignatures(IAdvancedSignature signature, IValidationContext ctx, IDocument? externalContent)
        {
            IList<IAdvancedSignature> counterSignatures = signature.CounterSignatures;
            if (counterSignatures == null)
            {
                return null;
            }
            List<SignatureVerification> counterSigVerifs = new List<SignatureVerification>();
            foreach (IAdvancedSignature counterSig in counterSignatures)
            {
                var counterSigSignatureValidationResult = new SignatureValidationResult(counterSig.CheckIntegrity(this.cryptographicProvider, externalContent));
                string counterSigAlg = counterSig.SignatureAlgorithm;
                counterSigVerifs.Add(new SignatureVerification(counterSigSignatureValidationResult, counterSigAlg));
            }
            return counterSigVerifs.ToArray();
        }

        /// <summary>
        /// Check the list of Timestamptoken.
        /// </summary>
        /// <remarks>Check the list of Timestamptoken. For each one a TimestampVerificationSignatureValidationResult is produced
        /// 	</remarks>
        /// <param name="signature"></param>
        /// <param name="referenceTime"></param>
        /// <param name="ctx"></param>
        /// <param name="tstokens"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        protected internal virtual IList<TimestampVerificationResult> VerifyTimestamps(
                DateTime endDate,
                IValidationContext ctx,
                ICertificateSource? optionalCertsSource,
                ICrlSource? optionalCRLSource,
                IOcspSource? optionalOCSPSource,
                IList<TimestampToken>? tstokens,
                byte[] data)
        {
            IList<TimestampVerificationResult> tstokenVerifs = new List<TimestampVerificationResult>();
            if (tstokens != null)
            {
                foreach (TimestampToken t in tstokens)
                {
                    TimestampVerificationResult verif = new TimestampVerificationResult(t);

                    if (t.MatchData(this.cryptographicProvider, data))
                    {
                        verif.SetSameDigest(new SignatureValidationResult(ResultStatus.VALID, null));
                    }
                    else
                    {
                        verif.SetSameDigest(new SignatureValidationResult(ResultStatus.INVALID, "$UI_Signatures_ValidationText_TimestampDontSignData"));
                    }
                    var signature = GetSignatures(t.GetTimeStamp().ToCmsSignedData()).First();
                    CheckTimeStampCertPath(
                            t,
                            endDate,
                            verif,
                            ctx,
                        new CompositeCertificateSource(signature.CertificateSource, optionalCertsSource),
                        new CompositeCrlSource(signature.CRLSource, optionalCRLSource),
                        new CompositeOcspSource(signature.OCSPSource, optionalOCSPSource));
                    tstokenVerifs.Add(verif);
                }
            }
            return tstokenVerifs;
        }

        protected internal virtual SignatureLevelBES VerifyLevelBES(IAdvancedSignature signature, IValidationContext ctx, IDocument? externalContent)
        {
            if (signature is null)
            {
                throw new ArgumentNullException(nameof(signature));
            }

            try
            {
                SignatureValidationResult signingCertRefVerification = new SignatureValidationResult();
                if (signature.SigningCertificate != null)
                {
                    signingCertRefVerification.SetStatus(ResultStatus.VALID, null);
                }
                else
                {
                    signingCertRefVerification.SetStatus(ResultStatus.INVALID, "$UI_Signatures_ValidationText_NoSigningCeritificate");
                }
                SignatureVerification[]? counterSigsVerif = VerifyCounterSignatures(signature, ctx, externalContent);
                SignatureValidationResult levelReached = new SignatureValidationResult(signingCertRefVerification.IsValid);

                return new SignatureLevelBES(levelReached, signature, signingCertRefVerification, counterSigsVerif, null);
            }
            catch (Exception)
            {
                return new SignatureLevelBES(
                    new SignatureValidationResult(ResultStatus.INVALID, "$UI_Signatures_ValidationText_ExceptionWhileVerifying"),
                    null,
                    new SignatureValidationResult(ResultStatus.INVALID, "$UI_Signatures_ValidationText_ExceptionWhileVerifying"),
                    null,
                    null);
            }
        }

        protected internal virtual SignatureLevelEPES VerifyLevelEPES(IAdvancedSignature signature, IValidationContext ctx)
        {
            try
            {
                PolicyValue? policyValue = signature.PolicyId;
                SignatureValidationResult levelReached = new SignatureValidationResult(policyValue != null);
                return new SignatureLevelEPES(signature, levelReached);
            }
            catch (Exception)
            {
                return new SignatureLevelEPES(signature, new SignatureValidationResult(ResultStatus.INVALID, "$UI_Signatures_ValidationText_ExceptionWhileVerifying"));
            }
        }

        private SignatureValidationResult ResultForTimestamps(IList<TimestampVerificationResult>? signatureTimestampsVerification, SignatureValidationResult levelReached)
        {
            nloglogger.Trace("ResultForTimestamps count: " + signatureTimestampsVerification?.Count);
            if (signatureTimestampsVerification == null || !signatureTimestampsVerification.Any())
            {
                levelReached.SetStatus(ResultStatus.INVALID, "$UI_Signatures_ValidationText_NoTimestamp");
            }
            else
            {
                levelReached.SetStatus(ResultStatus.VALID, null);
                foreach (TimestampVerificationResult result in signatureTimestampsVerification)
                {
                    if (result.SameDigest?.IsUndetermined ?? true)
                    {
                        nloglogger.Trace("$UI_Signatures_ValidationText_OneTimestampDigestUndetermined");
                        levelReached.SetStatus(ResultStatus.UNDETERMINED, "$UI_Signatures_ValidationText_OneTimestampDigestUndetermined");
                    }
                    else
                    {
                        if (result.SameDigest.IsInvalid)
                        {
                            levelReached.SetStatus(ResultStatus.INVALID, "$UI_Signatures_ValidationText_TimestampDontSignData");
                            break;
                        }
                        else if (result.CertPathVerification.IsUndetermined)
                        {
                            nloglogger.Trace("$UI_Signatures_ValidationText_RevocationUnknown resultfortimestamps");
                            levelReached.SetStatus(ResultStatus.UNDETERMINED, "$UI_Signatures_ValidationText_RevocationUnknown");
                        }
                        else if (result.CertPathVerification.IsInvalid)
                        {
                            levelReached.SetStatus(ResultStatus.INVALID, "$UI_Signatures_ValidationText_NoRevocationData");
                        }

                    }
                }
            }
            return levelReached;
        }

        protected internal virtual SignatureLevelT VerifyLevelT(
                IList<TimestampToken>? sigTimestamps,
                byte[] signatureTimestampData,
                DateTime endDate,
                IValidationContext ctx,
                ICertificateSource? optionalCertsSource,
                ICrlSource? optionalCRLSource,
                IOcspSource? optionalOCSPSource)
        {
            nloglogger.Trace("VerifyLevelT");
            IList<TimestampVerificationResult> results = VerifyTimestamps(
                    endDate,
                    ctx,
                    optionalCertsSource,
                    optionalCRLSource,
                    optionalOCSPSource,
                    sigTimestamps,
                    signatureTimestampData);
            return new SignatureLevelT(ResultForTimestamps(results, new SignatureValidationResult()), results);
        }

        private bool EveryCertificateRefAreThere(X509Certificate signingCert, IList<CertificateAndContext> certificates, IList<CertificateRef> certificateRefs)
        {
            nloglogger?.Info("EveryCertificateRefAreThere");
            foreach (CertificateAndContext neededCert in certificates)
            {
                if (neededCert.Certificate.Equals(signingCert))
                {
                    nloglogger?.Info("Don't check for the signing certificate");
                    continue;
                }
                nloglogger?.Info("Looking for the CertificateRef of " + neededCert);
                bool found = false;
                foreach (CertificateRef referencedCert in certificateRefs)
                {
                    nloglogger?.Info("Compare to " + referencedCert);
                    if (neededCert.Certificate.EqualsCertificateRef(this.cryptographicProvider, referencedCert))
                    {
                        found = true;
                        break;
                    }
                }
                nloglogger?.Info("Ref " + (found ? " found" : " not found"));
                if (!found)
                {
                    return false;
                }
            }
            return true;
        }

        protected internal virtual SignatureLevelC VerifyLevelC(
                X509Certificate signingCertificate,
                IList<CertificateRef> certificateRefs,
                IList<OCSPRef> ocspRefs,
                IList<CRLRef> crlRefs,
                IValidationContext ctx,
                DateTime startDate,
                DateTime endDate)
        {
            var cadesLogger = ctx.CadesLogger;

            try
            {
                SignatureValidationResult everyNeededCertAreInSignature = new SignatureValidationResult();

                var hashCode = signingCertificate.GetHashCode();
                if (!ctx.RevocationInfoDict.TryGetValue(hashCode, out var revocationInfo))
                {
                    cadesLogger.Error($"Revocation cert ref info for cert={signingCertificate.SubjectDN} is not found");

                    throw new ArgumentNullException("There is not a signing certificate");
                }
                var neededCerts = revocationInfo.GetCertsChain(signingCertificate, startDate, endDate);
                if (EveryCertificateRefAreThere(signingCertificate, neededCerts, certificateRefs))
                {
                    everyNeededCertAreInSignature.SetStatus(ResultStatus.VALID, null);
                }
                else
                {
                    everyNeededCertAreInSignature.SetStatus(ResultStatus.INVALID, "$UI_Signatures_ValidationText_NoAllNeededcertificateRef");
                }
                cadesLogger.Info("Every CertificateRef found " + everyNeededCertAreInSignature);
                SignatureValidationResult everyNeededRevocationData = new SignatureValidationResult(ResultStatus.VALID, null);
                SignatureValidationResult? levelCReached = null;
                var neededOcspResps = neededCerts.SelectMany(x =>
                {
                    var ocspResps = revocationInfo.GetRelatedOCSPResp(x, startDate, endDate);
                    nloglogger.Trace($"related ocsp resps ({ocspResps.Count}) for " + x);
                    return ocspResps;
                });
                if (!EveryOCSPValueOrRefAreThere(neededOcspResps, ocspRefs))
                {
                    everyNeededRevocationData.SetStatus(ResultStatus.INVALID, "$UI_Signatures_ValidationText_NoAllNeededOCSPRef");
                }
                var neededCrls = neededCerts.SelectMany(x => revocationInfo.GetRelatedCRLs(x, startDate, endDate));
                if (!EveryCRLValueOrRefAreThere(neededCrls, crlRefs))
                {
                    everyNeededRevocationData.SetStatus(ResultStatus.INVALID, "$UI_Signatures_ValidationText_NoAllNeededCRLRef");
                }
                levelCReached = new SignatureValidationResult(
                    everyNeededCertAreInSignature.Status == ResultStatus.VALID && everyNeededRevocationData.Status == ResultStatus.VALID);
                return new SignatureLevelC(levelCReached, everyNeededCertAreInSignature, everyNeededRevocationData);
            }
            catch (Exception e)
            {
                nloglogger.Error(e.Message + Environment.NewLine + e.StackTrace);
                return new SignatureLevelC(
                    new SignatureValidationResult(ResultStatus.INVALID, e.Message),
                    new SignatureValidationResult(ResultStatus.INVALID, e.Message),
                    new SignatureValidationResult(ResultStatus.INVALID, e.Message)
                    );
            }
        }

        private void CheckTimeStampCertPath(
                TimestampToken t,
                DateTime endDate,
                TimestampVerificationResult result,
                IValidationContext ctx,
                ICertificateSource certsSource,
                ICrlSource crlSource,
                IOcspSource ocspSource)
        {
            try
            {
                var timestampDate = t.GetTimeStamp().TimeStampInfo.GenTime;

                ctx.ValidateTimestamp(
                        t,
                        endDate,
                        certsSource,
                        crlSource,
                        ocspSource);
                var revocationInfo = ctx.RevocationInfoDict[t.GetHashCode()];
                result.UsedCerts = revocationInfo.GetCertsChain(t.GetSigner()!, timestampDate, endDate);

                var certificatePathVerification = new List<CertificateVerification>(
                        result.UsedCerts.SelectMany(x => x.CertificateVerifications));
                result.CertPathUpToTrustedList.SetStatus(ResultStatus.VALID, null);
                if (certificatePathVerification.Count != 0)
                {
                    foreach (CertificateVerification verif in certificatePathVerification)
                    {
                        if (verif.Summary.IsInvalid)
                        {

                            nloglogger.Trace("$UI_Signatures_ValidationText_CertificateIsNotValid");
                            result.CertPathUpToTrustedList.SetStatus(ResultStatus.INVALID, verif.Summary.Description ?? "$UI_Signatures_ValidationText_CertificateIsNotValid");
                            break;
                        }
                        if (verif.Summary.IsUndetermined)
                        {
                            nloglogger.Trace("$UI_Signatures_ValidationText_NoRevocationData");
                            nloglogger.Trace("st cert: " + verif.Certificate.SubjectDN + ", status startDate: " + verif.CertificateStatus.CertificateStatus.StartDate +
                                    " endDate: " + verif.CertificateStatus.CertificateStatus.EndDate);
                            result.CertPathUpToTrustedList.SetStatus(ResultStatus.UNDETERMINED, verif.Summary.Description ?? "$UI_Signatures_ValidationText_NoRevocationData");
                        }
                    }
                }
                else
                {
                    nloglogger.Trace("$UI_Signatures_ValidationText_NoRevocationData no certificate verifications");
                    result.CertPathUpToTrustedList.SetStatus(ResultStatus.UNDETERMINED, "$UI_Signatures_ValidationText_NoRevocationData");
                }
            }
            catch (IOException)
            {
                nloglogger.Trace("$UI_Signatures_ValidationText_ExceptionWhileVerifying");
                result.CertPathUpToTrustedList.SetStatus(ResultStatus.UNDETERMINED, "$UI_Signatures_ValidationText_ExceptionWhileVerifying");
            }
        }

        protected internal virtual SignatureLevelX VerifyLevelX(
                IList<TimestampToken>? timestampX1,
                byte[] timestampX1Data,
                IList<TimestampToken>? timestampX2,
                byte[] timestampX2Data,
                DateTime endDate,
                IValidationContext ctx,
                ICertificateSource? optionalCertsSource,
                ICrlSource? optionalCRLSource,
                IOcspSource? optionalOCSPSource)
        {
            try
            {
                SignatureValidationResult levelReached = new SignatureValidationResult();
                levelReached.SetStatus(ResultStatus.VALID, null);
                TimestampVerificationResult[]? x1Results = null;
                TimestampVerificationResult[]? x2Results = null;
                if (timestampX1 != null && timestampX1.Any())
                {
                    byte[] data = timestampX1Data;
                    x1Results = new TimestampVerificationResult[timestampX1.Count];
                    for (int i = 0; i < timestampX1.Count; i++)
                    {
                        TimestampToken t = timestampX1[i];
                        x1Results[i] = new TimestampVerificationResult(t);
                        if (!t.MatchData(this.cryptographicProvider, data))
                        {
                            levelReached.SetStatus(ResultStatus.INVALID, "$UI_Signatures_ValidationText_TimestampDontSignData");
                            x1Results[i].SetSameDigest(new SignatureValidationResult(ResultStatus.INVALID, "$UI_Signatures_ValidationText_TimestampDontSignData"));
                        }
                        else
                        {
                            x1Results[i].SetSameDigest(new SignatureValidationResult(ResultStatus.VALID, null));
                        }
                        var signature = GetSignatures(t.GetTimeStamp().ToCmsSignedData()).First();
                        CheckTimeStampCertPath(
                                t,
                                endDate,
                                x1Results[i],
                                ctx,
                        new CompositeCertificateSource(signature.CertificateSource, optionalCertsSource),
                        new CompositeCrlSource(signature.CRLSource, optionalCRLSource),
                        new CompositeOcspSource(signature.OCSPSource, optionalOCSPSource));
                    }
                }
                if (timestampX2 != null && timestampX2.Any())
                {
                    byte[] data = timestampX2Data;
                    x2Results = new TimestampVerificationResult[timestampX2.Count];
                    int i = 0;
                    foreach (TimestampToken t in timestampX2)
                    {
                        x2Results[i] = new TimestampVerificationResult(t);
                        if (!t.MatchData(this.cryptographicProvider, data))
                        {
                            levelReached.SetStatus(ResultStatus.INVALID, "$UI_Signatures_ValidationText_TimestampDontSignData");
                            x2Results[i].SetSameDigest(new SignatureValidationResult(ResultStatus.INVALID, "$UI_Signatures_ValidationText_TimestampDontSignData"));
                        }
                        else
                        {
                            x2Results[i].SetSameDigest(new SignatureValidationResult(ResultStatus.VALID, null));
                        }
                        var signature = GetSignatures(t.GetTimeStamp().ToCmsSignedData()).First();
                        CheckTimeStampCertPath(
                                t,
                                endDate,
                                x2Results[i],
                                ctx,
                        new CompositeCertificateSource(signature.CertificateSource, optionalCertsSource),
                        new CompositeCrlSource(signature.CRLSource, optionalCRLSource),
                        new CompositeOcspSource(signature.OCSPSource, optionalOCSPSource));
                    }
                }
                if ((timestampX1 == null || !timestampX1.Any()) && (timestampX2 == null || !timestampX2.Any()))
                {
                    levelReached.SetStatus(ResultStatus.INVALID, "$UI_Signatures_ValidationText_NoTimestamp");
                }
                return new SignatureLevelX(levelReached, x1Results, x2Results);
            }
            catch (Exception)
            {
                return new SignatureLevelX(new SignatureValidationResult(ResultStatus.INVALID, "$UI_Signatures_ValidationText_ExceptionWhileVerifying"));
            }
        }

        /// <summary>
        /// For level -XL, every certificates values contained in the IValidationContext (except the SigningCertificate) must
        /// be in the CertificatesValues of the signature
        /// </summary>
        /// <param name="ctx"></param>
        /// <param name="certificates"></param>
        /// <param name="signingCert"></param>
        /// <returns></returns>
        protected internal virtual bool EveryCertificateValueAreThere(IEnumerable<CertificateAndContext> neededCerts, IList<X509Certificate> refs)
        {
            foreach (CertificateAndContext neededCert in neededCerts)
            {
                nloglogger.Trace("EveryValue " + neededCert.Certificate.SubjectDN);
                nloglogger.Info("Looking for the certificate ref of " + neededCert);
                bool found = false;
                foreach (var referencedCert in refs)
                {
                    nloglogger.Info("Compare to " + referencedCert.SubjectDN);
                    if (referencedCert.Equals(neededCert.Certificate))
                    {
                        found = true;
                        break;
                    }
                }
                nloglogger.Info("Cert " + (found ? " found" : " not found"));
                if (!found)
                {
                    return false;
                }
            }
            return true;
        }

        protected internal virtual bool EveryOCSPValueOrRefAreThere<_T0>(IEnumerable<BasicOcspResp> neededOcspResp, IList<_T0> items)
        {
            foreach (var basicocspResp in neededOcspResp)
            {
                var ocspResp = new BasicOcspResp(basicocspResp.RefineOcspResp());
                nloglogger.Trace("Looking for the OcspResp produced at " + ocspResp.ProducedAt);
                bool found = false;
                foreach (var valueOrRef in items)
                {
                    if (valueOrRef is BasicOcspResp sigResp)
                    {
                        if (valueOrRef.Equals(ocspResp))
                        {
                            nloglogger.Trace("BasicOcspResp found");
                            found = true;
                            break;
                        }
                    }
                    else if (valueOrRef is OCSPRef @ref)
                    {
                        if (@ref.Match(this.cryptographicProvider, ocspResp))
                        {
                            nloglogger.Trace("OCSPRef found");
                            found = true;
                            break;
                        }
                    }
                }
                nloglogger.Trace("Ref" + (found ? " found" : " not found"));
                if (!found)
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// For level -XL, every X509Crl values contained in the IValidationContext must be in the RevocationValues of the
        /// signature
        /// </summary>
        /// <param name="ctx"></param>
        /// <param name="refs"></param>
        /// <param name="signingCert"></param>
        /// <returns></returns>
        protected internal virtual bool EveryCRLValueOrRefAreThere<_T0>(IEnumerable<X509Crl> needed, IList<_T0> items)
        {
            foreach (var crl in needed)
            {
                nloglogger.Trace("Looking for CRL ref issued by " + crl.IssuerDN);
                bool found = false;
                foreach (object? valueOrRef in items)
                {
                    if (valueOrRef is X509Crl sigCRL)
                    {
                        if (sigCRL.Equals(crl))
                        {
                            found = true;
                            break;
                        }
                    }
                    if (valueOrRef is CRLRef @ref)
                    {
                        if (@ref.Match(this.cryptographicProvider, crl))
                        {
                            found = true;
                            break;
                        }
                    }
                }
                nloglogger.Info("Ref " + (found ? " found" : " not found"));
                if (!found)
                {
                    return false;
                }
            }
            return true;
        }

        protected internal virtual SignatureLevelXL VerifyLevelXL(
                X509Certificate? signingCertificate,
                IList<X509Certificate> certificates,
                IList<BasicOcspResp> ocsps,
                IList<X509Crl> crls,
                IValidationContext ctx,
                DateTime startDate,
                DateTime endDate)
        {
            var logger = ctx.CadesLogger;
            try
            {
                SignatureValidationResult levelReached = new SignatureValidationResult();
                SignatureValidationResult everyNeededCertAreInSignature = new SignatureValidationResult();
                everyNeededCertAreInSignature.SetStatus(ResultStatus.VALID, null);
                SignatureValidationResult everyNeededRevocationData = new SignatureValidationResult();
                everyNeededRevocationData.SetStatus(ResultStatus.VALID, null);
                if (signingCertificate is null)
                {
                    throw new ArgumentException(nameof(signingCertificate));
                }
                var hashCode = signingCertificate.GetHashCode();
                if (!ctx.RevocationInfoDict.TryGetValue(hashCode, out var revocationInfo))
                {
                    logger?.Error($"Revocation cert ref info for cert={signingCertificate.SubjectDN} is not found");

                    throw new ArgumentNullException("There is not a signing certificate");
                }

                var neededCerts = revocationInfo.GetCertsChain(signingCertificate, startDate, endDate);
                if (!EveryCertificateValueAreThere(neededCerts, certificates))
                {
                    everyNeededCertAreInSignature.SetStatus(ResultStatus.INVALID, "$UI_Signatures_ValidationText_NoAllNeededCertificateValues");
                }

                logger?.Info("Every certificate found " + everyNeededCertAreInSignature);
                var neededOcspResps = neededCerts.SelectMany(x => revocationInfo.GetRelatedOCSPResp(x, startDate, endDate));
                if (!EveryOCSPValueOrRefAreThere(neededOcspResps, ocsps))
                {
                    everyNeededRevocationData.SetStatus(ResultStatus.INVALID, "$UI_Signatures_ValidationText_NoAllNeededOCSPValues");
                }
                var neededCrls = neededCerts.SelectMany(x => revocationInfo.GetRelatedCRLs(x, startDate, endDate));
                if (!EveryCRLValueOrRefAreThere(neededCrls, crls))
                {
                    everyNeededRevocationData.SetStatus(ResultStatus.INVALID, "$UI_Signatures_ValidationText_NoAllNeededCRLValues");
                }
                levelReached.SetStatus((everyNeededCertAreInSignature.Status == ResultStatus.VALID && everyNeededRevocationData.Status == ResultStatus.VALID) ?
                    ResultStatus.VALID : ResultStatus.INVALID, null);

                return new SignatureLevelXL(levelReached, everyNeededCertAreInSignature, everyNeededRevocationData);
            }
            catch (Exception)
            {
                return new SignatureLevelXL(
                    new SignatureValidationResult(ResultStatus.INVALID, "$UI_Signatures_ValidationText_ExceptionWhileVerifying"),
                    new SignatureValidationResult(ResultStatus.INVALID, "$UI_Signatures_ValidationText_ExceptionWhileVerifying"),
                    new SignatureValidationResult(ResultStatus.INVALID, "$UI_Signatures_ValidationText_ExceptionWhileVerifying"));
            }
        }

        protected internal virtual SignatureLevelA VerifyLevelA(
            IAdvancedSignature signature,
            DateTime endDate,
            IValidationContext ctx,
            ICertificateSource? optionalCertsSource,
            ICrlSource? optionalCRLSource,
            IOcspSource? optionalOCSPSource,
            IDocument? externalContent)
        {
            if (signature is null)
            {
                throw new ArgumentNullException(nameof(signature));
            }

            if (signature.ArchiveTimestamps is null)
            {
                return new SignatureLevelA(new SignatureValidationResult(ResultStatus.INVALID, "$UI_Signatures_ValidationText_NoArchiveTimestamps"), null);
            }
            if (externalContent is null)
            {
                return new SignatureLevelA(new SignatureValidationResult(ResultStatus.INVALID, "$UI_Signatures_ValidationText_NoOriginalDocument"), null);
            }

            // there should be different process of validation: need to check an ats hash and collect different data for timestamping
            // 1. validate ats hash: needed to calculate hashes for all certs, crls, unsigned attrs in ats_hash by order and for all values of the hash there should be values
            // 2. get all data for timestamp
            // 3. verify and path

            var results = new List<TimestampVerificationResult>();

            foreach (var ats in signature.ArchiveTimestamps.OrderByDescending(x => x.GetGenTimeDate()))
            {
                if (!CAdESProfileA.VerifyAtsHash(this.cryptographicProvider, signature, ats))
                {
                    var verif = new TimestampVerificationResult(ats);
                    verif.SetSameDigest(new SignatureValidationResult(ResultStatus.INVALID, "$UI_Signatures_ValidationText_AtsHashNotValid"));
                    results.Add(verif);
                    continue;

                }

                nloglogger.Trace($"Verify archive timestamp at time={endDate}");
                results.AddRange(VerifyTimestamps(
                        endDate,
                        ctx,
                        optionalCertsSource,
                        optionalCRLSource,
                        optionalOCSPSource,
                        new[] { ats },
                        CAdESProfileA.GetTimestampData(this.cryptographicProvider, signature, externalContent, ats)));

                endDate = ats.GetGenTimeDate();
            }

            return new SignatureLevelA(ResultForTimestamps(results, new SignatureValidationResult()), results);
        }

        /// <summary>
        /// Main method for validating a signature
        /// </summary>
        /// <param name="signature"></param>
        /// <param name="referenceTime"></param>
        /// <returns>
        /// the report part pertaining to the signature
        /// </returns>
        protected internal virtual (SignatureInformation?, IValidationContext?) ValidateSignature(
            IAdvancedSignature signature,
            IValidationContext? existedValidationContext,
            ICAdESLogger cadesLogger,
            bool checkIntegrity,
            IDocument? externalContent,
            DateTime? validationDate,
            RuntimeValidatingParams? runtimeValidatingParams)
        {
            if (signature is null)
            {
                throw new ArgumentNullException(nameof(signature));
            }

            if (signature.SigningCertificate == null)
            {
                return (null, null);
            }

            var endDate = this.CurrentTimeGetter.CurrentUtcTime;

            var unsignedAttributes = new OrderedAttributeTable(signature.SignerInformation.ToSignerInfo().UnauthenticatedAttributes);
            IValidationContext? ctx = existedValidationContext ?? validationContextFactory(signature.SigningCertificate, cadesLogger);
            SignatureVerification? signatureVerification = null;
            // TODO: should we use most recent or elder value. Or maybe we need to view this as many signatures in one?
            DateTime? tProfileTime = signature.SignatureTimestamps?.Select(x => x.GetGenTimeDate() as DateTime?).OrderBy(x => x).FirstOrDefault();
            var certPathStartDate = tProfileTime ?? signature.SigningTime?.Value ?? endDate;

            var levelA = VerifyLevelA(
                        signature,
                        endDate,
                        ctx,
                        signature.CertificateSource,
                        signature.CRLSource,
                        signature.OCSPSource,
                        externalContent);
            var levelATime = signature.ArchiveTimestamps?.Select(x => x.GetGenTimeDate() as DateTime?).OrderBy(x => x).FirstOrDefault();

            var oldOfflineMode = runtimeValidatingParams?.OfflineValidating ?? false;
            SignatureLevelX levelX;
            SignatureLevelT levelT;

            try
            {
                if (levelATime is not null)
                {
                    endDate = levelATime.Value;
                    if (runtimeValidatingParams is not null && !oldOfflineMode)
                    {
                        runtimeValidatingParams.OfflineValidating = true;
                    }
                }

                levelX = VerifyLevelX(
                        signature.TimestampsX1,
                        signature.TimestampX1Data,
                        signature.TimestampsX2,
                        signature.TimestampX2Data,
                        endDate,
                        ctx,
                        signature.CertificateSource,
                        signature.CRLSource,
                        signature.OCSPSource);
                var levelXTime =
                    signature.TimestampsX1?.Select(x => x.GetGenTimeDate() as DateTime?).OrderBy(x => x).FirstOrDefault() ??
                    signature.TimestampsX2?.Select(x => x.GetGenTimeDate() as DateTime?).OrderBy(x => x).FirstOrDefault();

                if (levelXTime is not null)
                {
                    endDate = levelXTime.Value;
                    if (runtimeValidatingParams is not null && !oldOfflineMode)
                    {
                        runtimeValidatingParams.OfflineValidating = true;
                    }
                }


                levelT = VerifyLevelT(
                        signature.SignatureTimestamps,
                        signature.SignatureTimestampData,
                        endDate,
                        ctx,
                        signature.CertificateSource,
                        signature.CRLSource,
                        signature.OCSPSource);

                signatureVerification = new SignatureVerification(
                        new SignatureValidationResult(!checkIntegrity || signature.CheckIntegrity(this.cryptographicProvider, externalContent)),
                        signature.SignatureAlgorithm);
                ctx.ValidateCertificate(
                        signature.CmsSignedData,
                        signature.SigningCertificate,
                        certPathStartDate,
                        endDate,
                        signature.CertificateSource,
                        signature.CRLSource,
                        signature.OCSPSource);
            }
            finally
            {
                if (runtimeValidatingParams is not null)
                {
                    runtimeValidatingParams.OfflineValidating = oldOfflineMode;
                }
            }

            var levelXL = VerifyLevelXL(
                    signature.SigningCertificate,
                    signature.Certificates,
                    signature.OCSPs,
                    signature.CRLs,
                    ctx,
                    certPathStartDate,
                    endDate);

            var levelC = VerifyLevelC(
                    signature.SigningCertificate,
                    signature.CertificateRefs,
                    signature.OCSPRefs,
                    signature.CRLRefs,
                    ctx,
                    certPathStartDate,
                    endDate);

            var signatureLevelAnalysis = new SignatureLevelAnalysis(
                signature,
                VerifyLevelBES(signature, ctx, externalContent),
                VerifyLevelEPES(signature, ctx),
                levelT,
                levelC,
                levelX,
                levelXL,
                levelA);

            var neededCerts = ctx.RevocationInfoDict.Values
                .SelectMany(x => x.NeededCertificateTokens.Select(y => y.CertificateAndContext));

            var revocationInfo = ctx.RevocationInfoDict[ctx.Certificate!.GetHashCode()];
            var certPathEndDate = endDate;
            var path = new CertPathRevocationAnalysis(
                    ctx,
                    revocationInfo.GetCertsChain(ctx.Certificate, certPathStartDate, certPathEndDate),
                    certPathStartDate,
                    certPathEndDate
                    );

            var signatureInformation = new SignatureInformation(
                signatureVerification!,
                path,
                signatureLevelAnalysis,
                ctx);
            return (signatureInformation, ctx);
        }

        /// <inheritdoc />
        public (ValidationReport, ICollection<IValidationContext?>) ValidateDocumentWithContext(
                IDocument document,
                bool checkIntegrity = true,
                IDocument? externalContent = null,
                ICollection<IValidationContext?>? validationContexts = null,
                RuntimeValidatingParams? runtimeValidatingParams = null)
        {
            var cmsSignedData = GetCmsSignedData(document);
            var verificationTime = this.CurrentTimeGetter.CurrentUtcTime;
            var timeInformation = new TimeInformation(verificationTime);
            var signatureInformationList = new List<SignatureInformation?>();
            var newValidationContexts = new List<IValidationContext?>();

            using var vcEnumerator = validationContexts?.GetEnumerator();
            foreach (IAdvancedSignature signature in GetSignatures(cmsSignedData))
            {
                IValidationContext? existedValidationContext = null;
                if (vcEnumerator?.MoveNext() ?? false)
                {
                    existedValidationContext = vcEnumerator?.Current;
                }
                var logger = loggerFactory();
                var (validationInfo, newValidationContext) = ValidateSignature(
                        signature,
                        existedValidationContext,
                        logger,
                        checkIntegrity,
                        externalContent,
                        verificationTime,
                        runtimeValidatingParams);
                if (validationInfo is not null)
                {
                    validationInfo.ValidationLog = logger.GetEntries();
                }

                signatureInformationList.Add(validationInfo);
                newValidationContexts.Add(newValidationContext);
            }
            return (new ValidationReport(timeInformation, signatureInformationList), newValidationContexts.ToArray());
        }

        /// <inheritdoc />
        public ValidationReport ValidateDocument(
                IDocument document,
                bool checkIntegrity = true,
                IDocument? externalContent = null,
                ICollection<IValidationContext?>? validationContexts = null,
                RuntimeValidatingParams? runtimeValidatingParams = null)
        {
            var (report, _) = this.ValidateDocumentWithContext(
                    document,
                    checkIntegrity,
                    externalContent,
                    validationContexts,
                    runtimeValidatingParams);
            return report;
        }
    }
}
