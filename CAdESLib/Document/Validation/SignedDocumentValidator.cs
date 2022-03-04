using CAdESLib.Document.Signature;
using CAdESLib.Helpers;
using Org.BouncyCastle.Asn1.X509.Qualified;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace CAdESLib.Document.Validation
{
    using ResultStatus = SignatureValidationResult.ResultStatus;

    public interface ISignedDocumentValidator
    {
        ValidationReport ValidateDocument(IDocument document, bool checkIntegrity = true, IDocument externalContent = null);
    }

    /// <summary>
    /// Validate the signed document
    /// </summary>
    public class SignedDocumentValidator : ISignedDocumentValidator
    {
        private readonly Func<ICAdESLogger> loggerFactory;
        private readonly Func<X509Certificate, DateTime, ICAdESLogger, IValidationContext> validationContextFactory;
        private const string SVC_INFO = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/SvcInfoExt/";

        /// <param>
        /// the certificateVerifier to set
        /// </param>
        public ICertificateVerifier CertificateVerifier { get; private set; }

        private readonly ICondition qcp = new PolicyIdCondition("0.4.0.1456.1.2");

        private readonly ICondition qcpplus = new PolicyIdCondition("0.4.0.1456.1.1");

        private readonly ICondition qccompliance = new QcStatementCondition(EtsiQCObjectIdentifiers.IdEtsiQcsQcCompliance);

        private readonly ICondition qcsscd = new QcStatementCondition(EtsiQCObjectIdentifiers.IdEtsiQcsQcSscd);

        public SignedDocumentValidator(ICertificateVerifier certificateVerifier, Func<ICAdESLogger> loggerFactory, Func<X509Certificate, DateTime, ICAdESLogger, IValidationContext> validationContextFactory)
        {
            CertificateVerifier = certificateVerifier;
            this.loggerFactory = loggerFactory;
            this.validationContextFactory = validationContextFactory;
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
        private IList<IAdvancedSignature> GetSignatures(CmsSignedData cmsSignedData)
        {
            var signatures = new List<IAdvancedSignature>();
            foreach (object o in cmsSignedData.GetSignerInfos().GetSigners())
            {
                SignerInformation i = (SignerInformation)o;
                CAdESSignature info = new CAdESSignature(cmsSignedData, i);
                signatures.Add(info);
            }
            return signatures;
        }

        protected internal virtual SignatureVerification[] VerifyCounterSignatures(IAdvancedSignature signature, IValidationContext ctx, IDocument externalContent)
        {
            IList<IAdvancedSignature> counterSignatures = signature.CounterSignatures;
            if (counterSignatures == null)
            {
                return null;
            }
            List<SignatureVerification> counterSigVerifs = new List<SignatureVerification>();
            foreach (IAdvancedSignature counterSig in counterSignatures)
            {
                var counterSigSignatureValidationResult = new SignatureValidationResult(counterSig.CheckIntegrity(externalContent));
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
        protected internal virtual IList<TimestampVerificationResult> VerifyTimestamps(IAdvancedSignature signature, IValidationContext ctx, IList<TimestampToken> tstokens, byte[] data)
        {
            IList<TimestampVerificationResult> tstokenVerifs = new List<TimestampVerificationResult>();
            if (tstokens != null)
            {
                foreach (TimestampToken t in tstokens)
                {
                    TimestampVerificationResult verif = new TimestampVerificationResult(t);

                    if (t.MatchData(data))
                    {
                        verif.SetSameDigest(new SignatureValidationResult(ResultStatus.VALID, null));
                    }
                    else
                    {
                        verif.SetSameDigest(new SignatureValidationResult(ResultStatus.INVALID, "$UI_Signatures_ValidationText_TimestampDontSignData"));
                    }
                    CheckTimeStampCertPath(t, verif, ctx, signature);
                    tstokenVerifs.Add(verif);
                }
            }
            return tstokenVerifs;
        }

        protected internal virtual SignatureLevelBES VerifyLevelBES(IAdvancedSignature signature, IValidationContext ctx, IDocument externalContent)
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
                SignatureVerification[] counterSigsVerif = VerifyCounterSignatures(signature, ctx, externalContent);
                SignatureValidationResult levelReached = new SignatureValidationResult(signingCertRefVerification.IsValid);

                return new SignatureLevelBES(levelReached, signature, signingCertRefVerification, counterSigsVerif, null);
            }
            catch (Exception)
            {
                return new SignatureLevelBES(new SignatureValidationResult(ResultStatus.INVALID, "$UI_Signatures_ValidationText_ExceptionWhileVerifying"), null, new SignatureValidationResult(ResultStatus.INVALID, "$UI_Signatures_ValidationText_ExceptionWhileVerifying"), null, null);
            }
        }

        protected internal virtual SignatureLevelEPES VerifyLevelEPES(IAdvancedSignature signature, IValidationContext ctx)
        {
            try
            {
                PolicyValue policyValue = signature.PolicyId;
                SignatureValidationResult levelReached = new SignatureValidationResult(policyValue != null);
                return new SignatureLevelEPES(signature, levelReached);
            }
            catch (Exception)
            {
                return new SignatureLevelEPES(signature, new SignatureValidationResult(ResultStatus.INVALID, "$UI_Signatures_ValidationText_ExceptionWhileVerifying"));
            }
        }

        private SignatureValidationResult ResultForTimestamps(IList<TimestampVerificationResult> signatureTimestampsVerification, SignatureValidationResult levelReached)
        {
            if (signatureTimestampsVerification == null || !signatureTimestampsVerification.Any())
            {
                levelReached.SetStatus(ResultStatus.INVALID, "$UI_Signatures_ValidationText_NoTimestamp");
            }
            else
            {
                levelReached.SetStatus(ResultStatus.VALID, null);
                foreach (TimestampVerificationResult result in signatureTimestampsVerification)
                {
                    if (result.SameDigest.IsUndetermined)
                    {
                        levelReached.SetStatus(ResultStatus.UNDETERMINED, "$UI_Signatures_ValidationText_OneTimestampDigestUndetermined");
                    }
                    else
                    {
                        if (result.SameDigest.IsInvalid)
                        {
                            levelReached.SetStatus(ResultStatus.INVALID, "$UI_Signatures_ValidationText_TimestampDontSignData");
                            break;
                        }
                    }
                }
            }
            return levelReached;
        }

        protected internal virtual SignatureLevelT VerifyLevelT(IAdvancedSignature signature, IValidationContext ctx)
        {
            if (signature is null)
            {
                throw new ArgumentNullException(nameof(signature));
            }

            IList<TimestampToken> sigTimestamps = signature.SignatureTimestamps;
            IList<TimestampVerificationResult> results = VerifyTimestamps(signature, ctx, sigTimestamps, signature.SignatureTimestampData);
            return new SignatureLevelT(ResultForTimestamps(results, new SignatureValidationResult()), results);
        }

        private bool EveryCertificateRefAreThere(IValidationContext ctx, IList<CertificateRef> refs, IList<TimestampToken> timestampTokens, ICAdESLogger logger)
        {
            foreach (CertificateAndContext neededCert in ctx.NeededCertificates)
            {
                if (neededCert.Certificate.Equals(ctx.Certificate)
                    || timestampTokens.Any(x => x.IsSignedBy(neededCert.Certificate)))
                {
                    logger.Info("Don't check for the signing certificate");
                    continue;
                }
                logger.Info("Looking for the CertificateRef of " + neededCert);
                bool found = false;
                foreach (CertificateRef referencedCert in refs)
                {
                    logger.Info("Compare to " + referencedCert);
                    byte[] hash = DigestUtilities.CalculateDigest(referencedCert.DigestAlgorithm, neededCert.Certificate.GetEncoded());
                    if (hash.SequenceEqual(referencedCert.DigestValue))
                    {
                        found = true;
                        break;
                    }
                }
                logger.Info("Ref " + (found ? " found" : " not found"));
                if (!found)
                {
                    return false;
                }
            }
            return true;
        }

        protected internal virtual SignatureLevelC VerifyLevelC(IAdvancedSignature signature, IValidationContext ctx, bool rehashValues, ICAdESLogger logger)
        {
            if (signature is null)
            {
                throw new ArgumentNullException(nameof(signature));
            }

            try
            {
                IList<CertificateRef> refs = signature.CertificateRefs;
                SignatureValidationResult everyNeededCertAreInSignature = new SignatureValidationResult();
                if (refs == null || !refs.Any())
                {
                    everyNeededCertAreInSignature.SetStatus(ResultStatus.INVALID, "$UI_Signatures_ValidationText_NoCertificateRef");
                }
                else
                {
                    if (EveryCertificateRefAreThere(ctx, refs, signature.AllTimestampTokens, logger))
                    {
                        everyNeededCertAreInSignature.SetStatus(ResultStatus.VALID, null);
                    }
                    else
                    {
                        everyNeededCertAreInSignature.SetStatus(ResultStatus.INVALID, "$UI_Signatures_ValidationText_NoAllNeededcertificateRef");
                    }
                }
                logger.Info("Every CertificateRef found " + everyNeededCertAreInSignature);
                IList<OCSPRef> ocspRefs = signature.OCSPRefs;
                IList<CRLRef> crlRefs = signature.CRLRefs;
                int refCount = 0;
                SignatureValidationResult everyNeededRevocationData = new SignatureValidationResult(ResultStatus.VALID, null);
                refCount += ocspRefs.Count;
                refCount += crlRefs.Count;
                SignatureValidationResult thereIsRevocationData = null;
                SignatureValidationResult levelCReached = null;
                if (rehashValues)
                {
                    if (!EveryOCSPValueOrRefAreThere(ctx, ocspRefs, logger))
                    {
                        everyNeededRevocationData.SetStatus(ResultStatus.INVALID, "$UI_Signatures_ValidationText_NoAllNeededOCSPRef");
                    }
                    if (!EveryCRLValueOrRefAreThere(ctx, crlRefs, logger))
                    {
                        everyNeededRevocationData.SetStatus(ResultStatus.INVALID, "$UI_Signatures_ValidationText_NoAllNeededCRLRef");
                    }
                    levelCReached = new SignatureValidationResult(
                        everyNeededCertAreInSignature.Status == ResultStatus.VALID && everyNeededRevocationData.Status == ResultStatus.VALID);
                    return new SignatureLevelC(levelCReached, everyNeededCertAreInSignature, everyNeededRevocationData);
                }
                else
                {
                    thereIsRevocationData = new SignatureValidationResult();
                    if (refCount == 0)
                    {
                        thereIsRevocationData.SetStatus(ResultStatus.INVALID, "$UI_Signatures_ValidationText_NoRevocationDataRefs");
                    }
                    else
                    {
                        thereIsRevocationData.SetStatus(ResultStatus.VALID, "$UI_Signatures_ValidationText_AtLeastOneRef");
                    }
                    levelCReached = new SignatureValidationResult(everyNeededCertAreInSignature.Status == ResultStatus.VALID && thereIsRevocationData.Status == ResultStatus.VALID);
                    return new SignatureLevelC(levelCReached, everyNeededCertAreInSignature, thereIsRevocationData);
                }
            }
            catch (Exception)
            {
                return new SignatureLevelC(
                    new SignatureValidationResult(ResultStatus.INVALID, "$UI_Signatures_ValidationText_ExceptionWhileVerifying"),
                    new SignatureValidationResult(ResultStatus.INVALID, "$UI_Signatures_ValidationText_ExceptionWhileVerifying"),
                    new SignatureValidationResult(ResultStatus.INVALID, "$UI_Signatures_ValidationText_ExceptionWhileVerifying")
                    );
            }
        }

        private void CheckTimeStampCertPath(TimestampToken t, TimestampVerificationResult result, IValidationContext ctx, IAdvancedSignature signature)
        {
            try
            {
                ctx.ValidateTimestamp(t, signature.CertificateSource, signature.CRLSource, signature.OCSPSource, result.UsedCerts);
                var certificatePathVerification = new List<CertificateVerification>();
                foreach (CertificateAndContext cert in result.UsedCerts)
                {
                    CertificateVerification verif = new CertificateVerification(cert, ctx);
                    certificatePathVerification.Add(verif);
                }
                result.CertPathUpToTrustedList.SetStatus(ResultStatus.VALID, null);
                if (certificatePathVerification != null && certificatePathVerification.Count != 0)
                {
                    foreach (CertificateVerification verif in certificatePathVerification)
                    {
                        if (verif.Summary.IsInvalid)
                        {
                            result.CertPathUpToTrustedList.SetStatus(ResultStatus.INVALID, verif.Summary.Description ?? "$UI_Signatures_ValidationText_CertificateIsNotValid");
                            break;
                        }
                        if (verif.Summary.IsUndetermined)
                        {
                            result.CertPathUpToTrustedList.SetStatus(ResultStatus.UNDETERMINED, verif.Summary.Description ?? "$UI_Signatures_ValidationText_NoRevocationData");
                        }
                    }
                }
                else
                {
                    result.CertPathUpToTrustedList.SetStatus(ResultStatus.UNDETERMINED, "$UI_Signatures_ValidationText_NoRevocationData");
                }
            }
            catch (IOException)
            {
                result.CertPathUpToTrustedList.SetStatus(ResultStatus.UNDETERMINED, "$UI_Signatures_ValidationText_ExceptionWhileVerifying");
            }
        }

        protected internal virtual SignatureLevelX VerifyLevelX(IAdvancedSignature signature, IValidationContext ctx)
        {
            if (signature is null)
            {
                throw new ArgumentNullException(nameof(signature));
            }

            try
            {
                SignatureValidationResult levelReached = new SignatureValidationResult();
                levelReached.SetStatus(ResultStatus.VALID, null);
                TimestampVerificationResult[] x1Results = null;
                TimestampVerificationResult[] x2Results = null;
                IList<TimestampToken> timestampX1 = signature.TimestampsX1;
                if (timestampX1 != null && timestampX1.Any())
                {
                    byte[] data = signature.TimestampX1Data;
                    x1Results = new TimestampVerificationResult[timestampX1.Count];
                    for (int i = 0; i < timestampX1.Count; i++)
                    {
                        TimestampToken t = timestampX1[i];
                        x1Results[i] = new TimestampVerificationResult(t);
                        if (!t.MatchData(data))
                        {
                            levelReached.SetStatus(ResultStatus.INVALID, "$UI_Signatures_ValidationText_TimestampDontSignData");
                            x1Results[i].SetSameDigest(new SignatureValidationResult(ResultStatus.INVALID, "$UI_Signatures_ValidationText_TimestampDontSignData"));
                        }
                        else
                        {
                            x1Results[i].SetSameDigest(new SignatureValidationResult(ResultStatus.VALID, null));
                        }
                        CheckTimeStampCertPath(t, x1Results[i], ctx, signature);
                    }
                }
                IList<TimestampToken> timestampX2 = signature.TimestampsX2;
                if (timestampX2 != null && timestampX2.Any())
                {
                    byte[] data = signature.TimestampX2Data;
                    x2Results = new TimestampVerificationResult[timestampX2.Count];
                    int i = 0;
                    foreach (TimestampToken t in timestampX2)
                    {
                        x2Results[i] = new TimestampVerificationResult(t);
                        if (!t.MatchData(data))
                        {
                            levelReached.SetStatus(ResultStatus.INVALID, "$UI_Signatures_ValidationText_TimestampDontSignData");
                            x2Results[i].SetSameDigest(new SignatureValidationResult(ResultStatus.INVALID, "$UI_Signatures_ValidationText_TimestampDontSignData"));
                        }
                        else
                        {
                            x2Results[i].SetSameDigest(new SignatureValidationResult(ResultStatus.VALID, null));
                        }
                        CheckTimeStampCertPath(t, x2Results[i], ctx, signature);

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
        protected internal virtual bool EveryCertificateValueAreThere(IValidationContext ctx, IList<X509Certificate> certificates, X509Certificate signingCert, ICAdESLogger logger)
        {
            foreach (CertificateAndContext neededCert in ctx.NeededCertificates)
            {
                if (neededCert.Certificate.Equals(signingCert))
                {
                    continue;
                }
                logger.Info("Looking for the certificate ref of " + neededCert);
                bool found = false;
                foreach (X509Certificate referencedCert in certificates)
                {
                    logger.Info("Compare to " + referencedCert.SubjectDN);
                    if (referencedCert.Equals(neededCert.Certificate))
                    {
                        found = true;
                        break;
                    }
                }
                logger.Info("Cert " + (found ? " found" : " not found"));
                if (!found)
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// For level -XL or C, every BasicOcspResponse values contained in the IValidationContext must be in the
        /// RevocationValues or the RevocationRef of the signature
        /// </summary>
        /// <param name="ctx"></param>
        /// <param name="refs"></param>
        /// <param name="signingCert"></param>
        /// <returns></returns>
        protected internal virtual bool EveryOCSPValueOrRefAreThere<_T0>(IValidationContext ctx, IList<_T0> ocspValuesOrRef, ICAdESLogger logger)
        {
            if (ctx is null)
            {
                throw new ArgumentNullException(nameof(ctx));
            }

            if (ocspValuesOrRef is null)
            {
                throw new ArgumentNullException(nameof(ocspValuesOrRef));
            }

            foreach (var ocspRespToken in ctx.NeededOCSPRespTokens)
            {
                var ocspResp = ocspRespToken.GetOcspResp();
                logger.Info("Looking for the OcspResp produced at " + ocspResp.ProducedAt);
                bool found = false;
                foreach (object valueOrRef in ocspValuesOrRef)
                {
                    if (valueOrRef is BasicOcspResp sigResp)
                    {
                        if (sigResp.Equals(ocspResp))
                        {
                            found = true;
                            break;
                        }
                    }
                    if (valueOrRef is OCSPRef @ref)
                    {
                        if (@ref.Match(ocspResp))
                        {
                            found = true;
                            break;
                        }
                    }
                }
                logger.Info("Ref " + (found ? " found" : " not found"));
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
        protected internal virtual bool EveryCRLValueOrRefAreThere<_T0>(IValidationContext ctx, IList<_T0> crlValuesOrRef, ICAdESLogger logger)
        {
            foreach (var crlToken in ctx.NeededCRLTokens)
            {
                var crl = crlToken.GetX509crl();
                logger.Info("Looking for CRL ref issued by " + crl.IssuerDN);
                bool found = false;
                foreach (object valueOrRef in crlValuesOrRef)
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
                        if (@ref.Match(crl))
                        {
                            found = true;
                            break;
                        }
                    }
                }
                logger.Info("Ref " + (found ? " found" : " not found"));
                if (!found)
                {
                    return false;
                }
            }
            return true;
        }

        protected internal virtual SignatureLevelXL VerifyLevelXL(IAdvancedSignature signature, IValidationContext ctx, ICAdESLogger logger)
        {
            try
            {
                SignatureValidationResult levelReached = new SignatureValidationResult();
                SignatureValidationResult everyNeededCertAreInSignature = new SignatureValidationResult();
                everyNeededCertAreInSignature.SetStatus(ResultStatus.VALID, null);
                SignatureValidationResult everyNeededRevocationData = new SignatureValidationResult();
                everyNeededRevocationData.SetStatus(ResultStatus.VALID, null);
                IList<X509Certificate> refs = signature.Certificates;
                if (!refs.Any())
                {
                    logger.Info("There is no certificate refs in the signature");
                    everyNeededCertAreInSignature.SetStatus(ResultStatus.INVALID, "$UI_Signatures_ValidationText_NoCertificateValue");
                }
                else
                {
                    if (!EveryCertificateValueAreThere(ctx, refs, signature.SigningCertificate, logger))
                    {
                        everyNeededCertAreInSignature.SetStatus(ResultStatus.INVALID, "$UI_Signatures_ValidationText_NoAllNeededCertificateValues");
                    }
                }
                logger.Info("Every certificate found " + everyNeededCertAreInSignature);
                int valueCount = 0;
                IList<BasicOcspResp> ocspValues = signature.OCSPs;
                if (ocspValues != null)
                {
                    valueCount += ocspValues.Count;
                    if (!EveryOCSPValueOrRefAreThere(ctx, ocspValues, logger))
                    {
                        everyNeededRevocationData.SetStatus(ResultStatus.INVALID, "$UI_Signatures_ValidationText_NoAllNeededOCSPValues");
                    }
                }
                IList<X509Crl> crlValues = signature.CRLs;
                if (crlValues != null)
                {
                    valueCount += crlValues.Count;
                    if (!EveryCRLValueOrRefAreThere(ctx, crlValues, logger))
                    {
                        everyNeededRevocationData.SetStatus(ResultStatus.INVALID, "$UI_Signatures_ValidationText_NoAllNeededCRLValues");
                    }
                }
                if (valueCount == 0)
                {
                    everyNeededRevocationData.SetStatus(ResultStatus.INVALID, "$UI_Signatures_ValidationText_NoRevocationDataValue");
                }
                levelReached.SetStatus((everyNeededCertAreInSignature.Status == ResultStatus.VALID && everyNeededRevocationData.Status == ResultStatus.VALID) ?
                    ResultStatus.VALID : ResultStatus.INVALID, null);
                return new SignatureLevelXL(levelReached, everyNeededCertAreInSignature, everyNeededRevocationData);
            }
            catch (Exception)
            {
                return new SignatureLevelXL(new SignatureValidationResult(ResultStatus.INVALID, "$UI_Signatures_ValidationText_ExceptionWhileVerifying"), new SignatureValidationResult(ResultStatus.INVALID, "$UI_Signatures_ValidationText_ExceptionWhileVerifying"), new SignatureValidationResult(ResultStatus.INVALID, "$UI_Signatures_ValidationText_ExceptionWhileVerifying"));
            }
        }

        protected internal virtual SignatureLevelA VerifyLevelA(IAdvancedSignature signature, IValidationContext ctx, ICAdESLogger logger, IDocument externalContent)
        {
            try
            {
                SignatureValidationResult levelReached = new SignatureValidationResult();
                IList<TimestampVerificationResult> verifs = null;
                try
                {
                    IList<TimestampToken> timestamps = signature.ArchiveTimestamps;
                    verifs = VerifyTimestamps(signature, ctx, timestamps, signature.GetArchiveTimestampData(0, externalContent));
                }
                catch (IOException e)
                {
                    logger.Error("Error verifyind level A " + e.Message);
                    levelReached.SetStatus(ResultStatus.UNDETERMINED, "$UI_Signatures_ValidationText_ExceptionWhileVerifying");
                }
                return new SignatureLevelA(ResultForTimestamps(verifs, levelReached), verifs);
            }
            catch (Exception)
            {
                return new SignatureLevelA(new SignatureValidationResult(ResultStatus.INVALID, "$UI_Signatures_ValidationText_ExceptionWhileVerifying"), null);
            }
        }

        protected internal virtual QualificationsVerification VerifyQualificationsElement(IAdvancedSignature signature, IValidationContext ctx)
        {
            SignatureValidationResult qCWithSSCD = new SignatureValidationResult();
            SignatureValidationResult qCNoSSCD = new SignatureValidationResult();
            SignatureValidationResult qCSSCDStatusAsInCert = new SignatureValidationResult();
            SignatureValidationResult qCForLegalPerson = new SignatureValidationResult();
            IList<string> qualifiers = ctx.GetQualificationStatement();
            if (qualifiers != null)
            {
                qCWithSSCD = new SignatureValidationResult(qualifiers.Contains(SVC_INFO + "QCWithSSCD"));
                qCNoSSCD = new SignatureValidationResult(qualifiers.Contains(SVC_INFO + "QCNoSSCD"));
                qCSSCDStatusAsInCert = new SignatureValidationResult(qualifiers.Contains(SVC_INFO + "QCSSCDStatusAsInCert"));
                qCForLegalPerson = new SignatureValidationResult(qualifiers.Contains(SVC_INFO + "QCForLegalPerson"));
            }
            return new QualificationsVerification(qCWithSSCD, qCNoSSCD, qCSSCDStatusAsInCert,
                qCForLegalPerson);
        }

        protected internal virtual QCStatementInformation VerifyQStatement(X509Certificate certificate)
        {
            if (certificate != null)
            {
                SignatureValidationResult qCPPresent = new SignatureValidationResult(qcp.Check(new CertificateAndContext(certificate)));
                SignatureValidationResult qCPPlusPresent = new SignatureValidationResult(qcpplus.Check(new CertificateAndContext(certificate)));
                SignatureValidationResult qcCompliancePresent = new SignatureValidationResult(qccompliance.Check(new CertificateAndContext(certificate)));
                SignatureValidationResult qcSCCDPresent = new SignatureValidationResult(qcsscd.Check(new CertificateAndContext(certificate)));
                return new QCStatementInformation(qCPPresent, qCPPlusPresent, qcCompliancePresent, qcSCCDPresent);
            }
            else
            {
                return new QCStatementInformation(null, null, null, null);
            }
        }

        /// <summary>
        /// Main method for validating a signature
        /// </summary>
        /// <param name="signature"></param>
        /// <param name="referenceTime"></param>
        /// <returns>
        /// the report part pertaining to the signature
        /// </returns>
        protected internal virtual SignatureInformation ValidateSignature(IAdvancedSignature signature, ICAdESLogger logger, SignatureValidationContext signatureValidationContext, bool checkIntegrity, IDocument externalContent)
        {
            if (signature is null)
            {
                throw new ArgumentNullException(nameof(signature));
            }

            if (signature.SigningCertificate == null)
            {
                logger.Error("There is no signing certificate");
                return null;
            }

            var signatureVerification = new SignatureVerification(new SignatureValidationResult(!checkIntegrity || signature.CheckIntegrity(externalContent)), signature.SignatureAlgorithm);
            IValidationContext ctx = signatureValidationContext.GetExisted(signature.SigningCertificate, signature.SigningTime?.Value ?? DateTime.Now);
            IList<CertificateAndContext> usedCerts = new List<CertificateAndContext>();
            SignatureLevelT levelT;
            Func<IValidationContext, SignatureLevelT> getLevelT = (IValidationContext ctx) =>
           {
               var levelT = VerifyLevelT(signature, ctx);
               if (!levelT.LevelReached.IsValid || !levelT.SignatureTimestampVerification.All(x => x.SameDigest.IsValid && x.CertPathVerification.IsValid))
               {
                   ctx.ValidationDate = DateTime.Now;
               }
               return levelT;
           };

            if (ctx == null)
            {
                var validationDate = signature.SignatureTimestamps?.FirstOrDefault()?.GetTimeStamp().TimeStampInfo.GenTime ?? DateTime.Now;
                ctx = validationContextFactory(signature.SigningCertificate, validationDate, logger);
                levelT = getLevelT(ctx);
                ctx = CertificateVerifier.ValidateCertificate(signature.SigningCertificate, ctx.ValidationDate, signature.CertificateSource, usedCerts, signature.CRLSource, signature.OCSPSource, logger, ctx);
                signatureValidationContext.Contexts.Add(ctx);
            }
            else
            {
                levelT = getLevelT(ctx);
                usedCerts = ctx.NeededCertificates.ToList();
            }

            var qcStatementInformation = VerifyQStatement(signature.SigningCertificate);
            var qualificationsVerification = VerifyQualificationsElement(signature, ctx);

            // TODO: serviceinfo is never set, so invalid everytime - hack added  - ?? new ServiceInfo()
            var info = new TrustedListInformation(ctx.GetRelevantServiceInfo() ?? new ServiceInfo());
            var path = new CertPathRevocationAnalysis(ctx, info, usedCerts);

            var signatureLevelXL = VerifyLevelXL(signature, ctx, logger);
            // order matters
            var signatureLevelC = VerifyLevelC(signature, ctx, signatureLevelXL?.LevelReached.IsValid ?? false, logger);
            var signatureLevelAnalysis = new SignatureLevelAnalysis(
                signature,
                VerifyLevelBES(signature, ctx, externalContent),
                VerifyLevelEPES(signature, ctx),
                levelT,
                signatureLevelC,
                VerifyLevelX(signature, ctx),
                signatureLevelXL,
                VerifyLevelA(signature, ctx, logger, externalContent));


            var signatureInformation = new SignatureInformation(signatureVerification, path, signatureLevelAnalysis, qualificationsVerification, qcStatementInformation, ctx.NeededCertificates.Select(cert => new CertificateVerification(cert, ctx)), ctx);
            return signatureInformation;

        }

        /// <summary>
        /// Validate the document and all its signatures
        /// </summary>
        /// <returns>
        /// the validation report
        /// </returns>
        public ValidationReport ValidateDocument(IDocument document, bool checkIntegrity = true, IDocument externalContent = null)
        {
            var cmsSignedData = GetCmsSignedData(document);
            var verificationTime = DateTime.Now;
            var timeInformation = new TimeInformation(verificationTime);
            var signatureInformationList = new List<SignatureInformation>();
            var context = new SignatureValidationContext();

            foreach (IAdvancedSignature signature in GetSignatures(cmsSignedData))
            {
                var logger = loggerFactory();
                var validationInfo = ValidateSignature(signature, logger, context, checkIntegrity, externalContent);
                validationInfo.ValidationLog = logger.GetEntries();

                signatureInformationList.Add(validationInfo);
            }
            return new ValidationReport(timeInformation, signatureInformationList);
        }

        protected internal class SignatureValidationContext
        {
            public IList<IValidationContext> Contexts { get; set; } = new List<IValidationContext>();
            public IValidationContext GetExisted(X509Certificate cert, DateTime validationDate)
            {
                return Contexts.FirstOrDefault(x => x.Certificate.Equals(cert) && x.ValidationDate.Equals(validationDate));
            }
        }
    }
}
