using CAdESLib.Helpers;
using NLog;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Linq;

namespace CAdESLib.Document.Validation
{
    public interface IValidationContext
    {
        ICAdESLogger CadesLogger { get; }
        X509Certificate? Certificate { get; }
        ICrlSource CrlSource { get; }
        IOcspSource OcspSource { get; }
        ICertificateSource TrustedListCertificatesSource { get; }

        // when certificate or timestamp validated save an instance to dictionary where a key is gethashcode of object for validation
        Dictionary<int, RevocationInfo> RevocationInfoDict { get; }

        void ValidateCertificate(
                CmsSignedData cms,
                X509Certificate certificate,
                DateTime startDate,
                DateTime endDate,
                ICertificateSource certificateSource,
                ICrlSource crlSource,
                IOcspSource ocspSource);
        void ValidateTimestamp(
                TimestampToken timestamp,
                DateTime endDate,
                ICertificateSource certificateSource,
                ICrlSource crlSource,
                IOcspSource ocspSource);
    }

    /// <summary>
    /// During the validation of a certificate, the software retrieve differents X509 artifact like Certificate, CRL and OCSP
    /// Response.
    /// </summary>
    /// <remarks>
    /// During the validation of a certificate, the software retrieve differents X509 artifact like Certificate, CRL and OCSP
    /// Response. The ValidationContext is a "cache" for one validation request that contains every object retrieved so far.
    /// </remarks>
    public class ValidationContext : IValidationContext
    {
        private const string WasExpiredMessage = "Was expired";
        private const string WasNotYetValidMessage = "Was not yet valid";
        private static readonly Logger nloglogger = LogManager.GetCurrentClassLogger();

        public ICAdESLogger CadesLogger { get; private set; }
        public X509Certificate? Certificate { get; }
        public Dictionary<int, RevocationInfo> RevocationInfoDict { get; } = new Dictionary<int, RevocationInfo>();

        private readonly Func<CmsSignedData, IOcspSource, ICrlSource, ICertificateStatusVerifier> certificateVerifierFactory;
        private readonly Func<CertificateAndContext, CertificateToken> certificateTokenFactory;
        public ICrlSource CrlSource { get; set; }
        public IOcspSource OcspSource { get; set; }
        public ICertificateSource TrustedListCertificatesSource { get; set; }

        public HashSet<X509Certificate> KnownCerts { get; } = new HashSet<X509Certificate>();
        public HashSet<X509Crl> KnownCrls { get; } = new HashSet<X509Crl>();
        public HashSet<BasicOcspResp> KnownOcsps { get; } = new HashSet<BasicOcspResp>();

        /// <summary>
        /// The default constructor for ValidationContextV2.
        /// </summary>
        /// <param>
        /// The certificate that will be validated.
        /// </param>
        public ValidationContext(
            X509Certificate? certificate,
            ICAdESLogger cadesLogger,
            IOcspSource ocspSource,
            ICrlSource crlSource,
            ICertificateSource certificateSource,
            Func<CmsSignedData, IOcspSource, ICrlSource, ICertificateStatusVerifier> certificateVerifierFactory,
            Func<CertificateAndContext, CertificateToken> certificateTokenFactory)
        {
            this.certificateTokenFactory = certificateTokenFactory;
            this.OcspSource = ocspSource;
            this.CrlSource = crlSource;
            this.TrustedListCertificatesSource = certificateSource;
            this.CadesLogger = cadesLogger;
            if (certificate != null)
            {
                CadesLogger.Info($"New context for {certificate.SubjectDN}, {certificate.SerialNumber.ToString(16)}");
                this.Certificate = certificate;
            }
            this.certificateVerifierFactory = certificateVerifierFactory;
        }

        internal static CertificateAndContext? GetIssuerCertificate(
                ISignedToken signedToken,
                ICertificateSource optionalSource,
                ICAdESLogger cadesLogger,
                IList<X509Name> notFoundIssuers,
                ICertificateSource? trustedListCertificatesSource)
        {
            var issuerSubjectName = signedToken?.GetSignerSubjectName();
            if (signedToken is null || issuerSubjectName != null && notFoundIssuers.Contains(issuerSubjectName))
            {
                return null;
            }


            cadesLogger.Info("get issuer certificate by name " + issuerSubjectName);
            DateTime validationDate = signedToken.ThisUpdate;
            cadesLogger.Info("validationDate: " + validationDate);

            var list = new CompositeCertificateSource(trustedListCertificatesSource, optionalSource).GetCertificateBySubjectName(issuerSubjectName);
            if (list != null)
            {
                foreach (CertificateAndContext cert in list)
                {
                    cadesLogger.Info($"Potential issuer: {cert.ToString()}");
                    try
                    {
                        cert.Certificate.CheckValidity(validationDate);
                    }
                    catch (CertificateExpiredException)
                    {
                        cadesLogger.Info(WasExpiredMessage);
                        cadesLogger.Info($"validationDate={validationDate} notBefore={cert.Certificate.NotBefore}, notAfter={cert.Certificate.NotAfter}");
                        continue;
                    }
                    catch (CertificateNotYetValidException)
                    {
                        cadesLogger.Info(WasNotYetValidMessage);
                        cadesLogger.Info($"validationDate={validationDate} notBefore={cert.Certificate.NotBefore}, notAfter={cert.Certificate.NotAfter}");
                        continue;
                    }
                    if (signedToken.IsSignedBy(cert.Certificate))
                    {
                        cadesLogger.Info($"Issuer found: {cert.ToString()}");
                        return cert;
                    }
                }
            }

            cadesLogger.Warn("Don't found any issuer for token " + signedToken);
            if (issuerSubjectName != null)
            {
                notFoundIssuers.Add(issuerSubjectName);
            }

            return null;
        }
        /// <summary>
        /// Validate the timestamp
        /// </summary>
        public virtual void ValidateCertificate(
                CmsSignedData cms,
                X509Certificate certificate,
                DateTime startDate,
                DateTime endDate,
                ICertificateSource certificateSource,
                ICrlSource crlSource,
                IOcspSource ocspSource)
        {
            if (certificate is null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            CertificateAndContext? trustedCert = null;
            var possibleCerts = TrustedListCertificatesSource?.GetCertificateBySubjectName(certificate.SubjectDN);
            if (possibleCerts != null)
            {
                foreach (var c in possibleCerts)
                {
                    if (certificate.IsSignedBy(c.Certificate))
                    {
                        trustedCert = c;
                        break;
                    }
                }
            }

            var certToVerify = trustedCert;
            if (certToVerify is null)
            {
                certToVerify = CertificateAndContext.GetInstance(certificate);
                certToVerify.RootCause.Add(certificate);
            }

            var hashCode = certificate.GetHashCode();

            var revocationInfo = AddAndGetRevocationInfo(hashCode);

            revocationInfo.AddNotYetVerifiedToken(
                    certificateTokenFactory(certToVerify),
                    this.CadesLogger);

            IList<X509Name> notFoundIssuers = new List<X509Name>();

            Validate(
                cms,
                certificate,
                startDate,
                endDate,
                certificateSource,
                crlSource,
                ocspSource,
                revocationInfo,
                notFoundIssuers);
        }

        private RevocationInfo AddAndGetRevocationInfo(int hashCode)
        {
            var revocationInfo = RevocationInfoDict.ContainsKey(hashCode) ?
                RevocationInfoDict[hashCode] :
                (RevocationInfoDict[hashCode] = new RevocationInfo());

            return revocationInfo;
        }


        /// <summary>
        /// Validate the timestamp
        /// </summary>
        public virtual void ValidateTimestamp(
            TimestampToken timestamp,
            DateTime endDate,
            ICertificateSource certificateSource,
            ICrlSource crlSource,
            IOcspSource ocspSource)
        {
            if (timestamp is null)
            {
                throw new ArgumentNullException(nameof(timestamp));
            }

            IList<X509Name> notFoundIssuers = new List<X509Name>();
            var hashCode = timestamp.GetHashCode();
            var revocationInfo = AddAndGetRevocationInfo(hashCode);

            revocationInfo.AddNotYetVerifiedToken(timestamp, this.CadesLogger);
            CadesLogger.Trace("validateTimestamp time=" + timestamp.GetTimeStamp().TimeStampInfo.GenTime + ", hashCode=" + hashCode + ", revocationInfo=" + revocationInfo.GetHashCode());
            Validate(
                timestamp.GetTimeStamp().ToCmsSignedData(),
                timestamp,
                timestamp.GetTimeStamp().TimeStampInfo.GenTime,
                endDate,
                certificateSource,
                crlSource,
                ocspSource,
                revocationInfo,
                notFoundIssuers);
        }

        /// <summary>
        /// Build the validation context for the specific date
        /// </summary>
        public void Validate(
            CmsSignedData cms,
            object rootValidationCause,
            DateTime startDate,
            DateTime endDate,
            ICertificateSource certificateSource,
            ICrlSource crlSource,
            IOcspSource ocspSource,
            RevocationInfo revocationInfo,
            IList<X509Name> notFoundIssuers)
        {
            int previousSize = revocationInfo.Count;
            int previousVerified = revocationInfo.VerifiedTokenCount;
            var signedTokenAndRevData = revocationInfo.GetOneNotYetVerifiedToken(CadesLogger);
            if (signedTokenAndRevData is not null)
            {
                var signedToken = signedTokenAndRevData.TargetToken;
                CadesLogger.Trace($"signedToken: {signedToken}");
                CadesLogger.Trace($"rootValidationCause: {rootValidationCause.GetType()}, signedTokenType: {signedToken.GetType()}, signedToken: {signedToken}");
                // TODO: for certificateToken the source is aia, so put it at position of last resort (will be valuable to rearange composite sources so sources that use network connection will be used at a last time)
                ICertificateSource otherSource = new CompositeCertificateSource(
                        new ListCertificateSource(KnownCerts.ToList()),
                        new ListCertificateSource(revocationInfo.NeededCertificateTokens.Select(x => x.Certificate).ToList()),
                        certificateSource,
                        signedToken.GetWrappedCertificateSource());
                CertificateAndContext? issuer = GetIssuerCertificate(
                        signedToken,
                        otherSource,
                        CadesLogger,
                        notFoundIssuers,
                        TrustedListCertificatesSource);

                if (issuer != null)
                {
                    CadesLogger.Trace($"issuer: {issuer}");
                    KnownCerts.Add(issuer.Certificate);
                    var alreadyProcessed = revocationInfo.NeededCertificateTokens
                        .FirstOrDefault(certificate => certificate.Certificate.Equals(issuer.Certificate));

                    if (alreadyProcessed is null || revocationInfo.RevocationDataOutdated(issuer, startDate, endDate))
                    {
                        CadesLogger.Trace($"NOT already processed");
                        issuer.RootCause.Add(rootValidationCause);
                        var certToken = certificateTokenFactory(issuer);
                        var revocationData = revocationInfo.AddNotYetVerifiedToken(certToken, CadesLogger);
                        if (issuer.Certificate.SubjectDN.Equals(issuer.Certificate.IssuerDN) && issuer.Certificate.IsSignedBy(issuer.Certificate))
                        {
                            ISignedToken trustedToken = certToken;
                            CertificateSourceType certificateSourceType;
                            CertificateValidity validity;
                            ValidatorSourceType validationSourceType;
                            if (issuer.CertificateSource == CertificateSourceType.TRUSTED_LIST)
                            {
                                certificateSourceType = CertificateSourceType.TRUSTED_LIST;
                                validity = CertificateValidity.VALID;
                                validationSourceType = ValidatorSourceType.TRUSTED_LIST;
                            }
                            else
                            {
                                certificateSourceType = CertificateSourceType.NOT_TRUSTED_LIST;
                                validity = CertificateValidity.UNKNOWN;
                                validationSourceType = ValidatorSourceType.NOT_TRUSTED_LIST;
                                CadesLogger.Trace("not trusted self-signed cert: " + Convert.ToBase64String(issuer.Certificate.GetEncoded()));
                            }
                            revocationData.RevocationDataAsCertificateSourceType = certificateSourceType;

                            var locCertAndContext = certToken.CertificateAndContext;
                            locCertAndContext.CertificateVerifications.Add(
                                    new CertificateVerification(
                                        revocationInfo,
                                        locCertAndContext,
                                        signedToken.ThisUpdate,
                                        endDate,
                                        this,
                                        new CertificateStatus()
                                        {
                                            Validity = validity,
                                            StartDate = startDate,
                                            EndDate = endDate,
                                            StatusSourceType = validationSourceType
                                        }));
                        }
                    }
                    else
                    {
                        CadesLogger.Trace($"already processed");
                        issuer = alreadyProcessed.CertificateAndContext;

                        if (rootValidationCause is X509Certificate && !issuer.RootCause.Any(x => x is X509Certificate))
                        {
                            CadesLogger.Trace($"Root cause is not X509Certificate");
                            issuer.RootCause.Add(rootValidationCause);
                            foreach (var c in revocationInfo.GetCertsChain(issuer, startDate, endDate))
                            {
                                CadesLogger.Trace($"Root cause in cert chain, cert: {c}");
                                c.RootCause.Add(rootValidationCause);
                                foreach (var crlt in revocationInfo.GetRelatedCRLTokens(c, startDate, endDate))
                                {
                                    CadesLogger.Trace($"Root cause in cert chain, related crl: {crlt}");
                                    crlt.RootCause.Add(rootValidationCause);
                                }
                                foreach (var crlt in revocationInfo.GetRelatedOCSPRespTokens(c, startDate, endDate))
                                {
                                    CadesLogger.Trace($"Root cause in cert chain, related ocsp: {crlt}");
                                    crlt.RootCause.Add(rootValidationCause);
                                }
                            }
                        }
                    }
                }

                if (signedToken is CertificateToken ct)
                {
                    var certAndContext = ct.CertificateAndContext;
                    certAndContext.IssuerCertificate = issuer;
                    CadesLogger.Trace($"get cert status startDate={startDate}, endDate={endDate} for {certAndContext.Certificate.SubjectDN}");
                    var verifier = certificateVerifierFactory(cms,
                                    new CompositeOcspSource(
                                        ocspSource,
                                        // TODO: There is a problem when extend to an A: for a X timestamp we get ocsp from a T timestamp and it's valid by time but some cert in chain is outdated we get this ocsp in work and when we figure out that  path is incorrect we not try to get a fresh one - need to be more adaptive 
                                        // new ListOCSPSource(KnownOcsps.ToList()),
                                        OcspSource),
                                    new CompositeCrlSource(
                                        crlSource,
                                        new ListCRLSource(KnownCrls.ToList()),
                                        CrlSource));
                    CertificateStatus? status =
                        verifier.Check(certAndContext.Certificate, issuer?.Certificate, startDate, endDate)
                                     ?? CertificateStatus.GetNotAvailableStatus(certAndContext.Certificate, startDate, endDate);

                    CadesLogger.Warn($"status startDate={status.StartDate}, endDate={endDate}, status={status.Validity} for {status.Certificate!.SubjectDN}");
                    certAndContext.CertificateVerifications.Add(
                            new CertificateVerification(
                                revocationInfo,
                                certAndContext,
                                // for case of an out of date certificate
                                startDate,
                                endDate,
                                this,
                                status));

                    signedTokenAndRevData.RevocationDataAsStatusSource = status.StatusSource;
                    if (status.StatusSource.Source is X509Crl crl)
                    {
                        CadesLogger.Trace("crl status");
                        KnownCrls.Add(crl);
                        revocationInfo.AddNotYetVerifiedToken(
                                new CRLToken(crl, rootValidationCause),
                                CadesLogger);
                    }
                    else if (status.StatusSource.Source is BasicOcspResp resp)
                    {
                        CadesLogger.Trace("ocsp status");
                        KnownOcsps.Add(resp);
                        if (status.StatusSourceType != ValidatorSourceType.OCSP_NO_CHECK)
                        {
                            revocationInfo.AddNotYetVerifiedToken(
                                    new OCSPRespToken(resp, rootValidationCause),
                                    CadesLogger);
                        }
                    }
                    else
                    {
                        CadesLogger.Trace("No status for " + signedToken);
                    }
                }
                else
                {
                    if (signedToken is CRLToken || signedToken is OCSPRespToken || signedToken is TimestampToken)
                    {
                        signedTokenAndRevData.RevocationDataAsCertificate = issuer;
                    }
                    else
                    {
                        throw new Exception("Not supported token type " + signedToken.GetType().Name);
                    }
                }

                CadesLogger.Info(revocationInfo.ToString());
                int newSize = revocationInfo.Count;
                int newVerified = revocationInfo.VerifiedTokenCount;
                if (newSize != previousSize || newVerified != previousVerified)
                {
                    Validate(
                            cms,
                            rootValidationCause,
                            startDate,
                            endDate,
                            certificateSource,
                            crlSource,
                            ocspSource,
                            revocationInfo,
                            notFoundIssuers);
                }
            }
        }
    }
}
