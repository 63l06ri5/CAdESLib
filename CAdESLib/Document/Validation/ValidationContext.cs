using CAdESLib.Helpers;
using NLog;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace CAdESLib.Document.Validation
{
    public interface IValidationContext
    {
        IList<BasicOcspResp> NeededOCSPResp { get; }
        IList<OCSPRespToken> NeededOCSPRespTokens { get; }
        X509Certificate? Certificate { get; }
        IList<X509Crl> NeededCRL { get; }
        IList<CRLToken> NeededCRLTokens { get; }
        IList<CertificateAndContext> NeededCertificates { get; }
        IList<CertificateToken> NeededCertificateTokens { get; }
        DateTime ValidationDate { get; set; }
        ICrlSource CrlSource { get; }
        IOcspSource OcspSource { get; }
        ICertificateSource TrustedListCertificatesSource { get; }
        IDictionary<ISignedToken, RevocationData?> RevocationInfo { get; }
        IList<X509Name> NotFoundIssuers { get; }
        void ValidateCertificate(X509Certificate certificate, DateTime validationDate, ICertificateSource? optionalSource, ICrlSource? optionalCRLSource, IOcspSource? optionalOCSPSource, IList<CertificateAndContext> usedCerts);
        IList<X509Crl> GetRelatedCRLs(CertificateAndContext cert);
        IList<CRLToken> GetRelatedCRLTokens(CertificateAndContext cert);
        IList<BasicOcspResp> GetRelatedOCSPResp(CertificateAndContext cert);
        IList<OCSPRespToken> GetRelatedOCSPRespTokens(CertificateAndContext cert);
        void ValidateTimestamp(TimestampToken timestamp, ICertificateSource? optionalSource, ICrlSource? optionalCRLSource, IOcspSource? optionalOCPSSource, IList<CertificateAndContext> usedCerts);
        CertificateAndContext? GetParentFromTrustedList(CertificateAndContext ctx);
        IList<string>? GetQualificationStatement();
        ServiceInfo? GetRelevantServiceInfo();
        CertificateStatus? GetCertificateStatusFromContext(CertificateAndContext cert);
        SignatureValidationResult GetOcspStatus(BasicOcspResp x);
        SignatureValidationResult GetCrlStatus(CRLToken crlToken);
        List<CertificateAndContext> GetCertsChain(CertificateAndContext certificateAndContext, List<CertificateAndContext>? certSet = null);
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
        private const string WasNotValidTSLMessage = "Was not valid in the TSL";
        private const string VerifyWithOfflineServiceMessage = "Verify with offline services";
        private const string VerifyWithOnlineServiceMessage = "Verify with online services";
        private readonly ICAdESLogger? logger;
        private static readonly Logger nloglogger = LogManager.GetCurrentClassLogger();

        public IList<BasicOcspResp> NeededOCSPResp => NeededOCSPRespTokens.Select(x => x.GetOcspResp()).ToList();
        public IList<OCSPRespToken> NeededOCSPRespTokens { get; } = new List<OCSPRespToken>();
        public X509Certificate? Certificate { get; }
        public IList<X509Crl> NeededCRL => NeededCRLTokens.Select(x => x.GetX509crl()).ToList();
        public IList<CRLToken> NeededCRLTokens { get; } = new List<CRLToken>();
        public IList<CertificateAndContext> NeededCertificates => NeededCertificateTokens.Select(x => x.GetCertificateAndContext()).ToList();
        public IList<CertificateToken> NeededCertificateTokens { get; } = new List<CertificateToken>();
        public IDictionary<ISignedToken, RevocationData?> RevocationInfo { get; } = new Dictionary<ISignedToken, RevocationData?>();


        public DateTime ValidationDate { get; set; }


        private readonly Func<IOcspSource?, ICrlSource?, ICertificateStatusVerifier> certificateVerifierFactory;
        private readonly Func<CertificateAndContext, CertificateToken> certificateTokenFactory;
        public ICrlSource CrlSource { get; set; }
        public IOcspSource OcspSource { get; set; }
        public ICertificateSource TrustedListCertificatesSource { get; set; }

        public IList<X509Name> NotFoundIssuers { get; } = new List<X509Name>();

        /// <summary>
        /// The default constructor for ValidationContextV2.
        /// </summary>
        /// <param>
        /// The certificate that will be validated.
        /// </param>
        public ValidationContext(
            X509Certificate? certificate,
            DateTime validationDate,
            ICAdESLogger? cadesLogger,
            IOcspSource ocspSource,
            ICrlSource crlSource,
            ICertificateSource certificateSource,
            Func<IOcspSource?, ICrlSource?, ICertificateStatusVerifier> certificateVerifierFactory,
            Func<CertificateAndContext, CertificateToken> certificateTokenFactory)
        {
            this.certificateTokenFactory = certificateTokenFactory;
            this.OcspSource = ocspSource;
            this.CrlSource = crlSource;
            this.TrustedListCertificatesSource = certificateSource;
            this.logger = cadesLogger;
            if (certificate != null)
            {
                logger?.Info($"New context for {certificate.SubjectDN}, {certificate.SerialNumber.ToString(16)}");
                this.Certificate = certificate;
            }
            this.ValidationDate = validationDate;
            this.certificateVerifierFactory = certificateVerifierFactory;
        }

        internal virtual ISignedToken? GetOneNotYetVerifiedToken()
        {
            foreach (var e in RevocationInfo)
            {
                if (e.Value == null)
                {
                    logger?.Info("=== Get token to validate " + e.Key);
                    return e.Key;
                }
            }
            return null;
        }

        internal virtual CertificateAndContext? GetIssuerCertificate(ISignedToken signedToken, ICertificateSource optionalSource, DateTime validationDate)
        {
            var issuerSubjectName = signedToken?.GetSignerSubjectName();
            if (signedToken is null || issuerSubjectName == null || NotFoundIssuers.Contains(issuerSubjectName))
            {
                return null;
            }

            var list = new CompositeCertificateSource(TrustedListCertificatesSource, optionalSource).GetCertificateBySubjectName(issuerSubjectName);
            if (list != null)
            {
                foreach (CertificateAndContext cert in list)
                {
                    logger?.Info($"Potential issuer: {cert.ToString()}");
                    if (validationDate != null)
                    {
                        try
                        {
                            cert.Certificate.CheckValidity(validationDate);
                        }
                        catch (CertificateExpiredException)
                        {
                            logger?.Info(WasExpiredMessage);
                            continue;
                        }
                        catch (CertificateNotYetValidException)
                        {
                            logger?.Info(WasNotYetValidMessage);
                            continue;
                        }
                        if (cert.CertificateSource == CertificateSourceType.TRUSTED_LIST && cert.Certificate.IsSignedBy(cert.Certificate) && cert.Context != null)
                        {
                            ServiceInfo info = (ServiceInfo)cert.Context;
                            if (info.StatusStartingDateAtReferenceTime != null && validationDate.CompareTo(
                                info.StatusStartingDateAtReferenceTime) < 0)
                            {
                                logger?.Info(WasNotValidTSLMessage);
                                continue;
                            }
                            else
                            {
                                if (info.StatusEndingDateAtReferenceTime != null
                                 && validationDate.CompareTo(info.StatusEndingDateAtReferenceTime) > 0)
                                {
                                    logger?.Info(WasNotValidTSLMessage);
                                    continue;
                                }
                            }
                        }
                    }
                    if (signedToken.IsSignedBy(cert.Certificate))
                    {
                        logger?.Info($"Issuer: {cert.ToString()}");
                        return cert;
                    }
                }
            }

            logger?.Warn("Don't found any issuer for token " + signedToken);
            NotFoundIssuers.Add(issuerSubjectName);

            return null;
        }

        internal void AddNotYetVerifiedToken(ISignedToken signedToken)
        {
            if (!RevocationInfo.ContainsKey(signedToken))
            {
                logger?.Info("New token to validate " + signedToken + " hashCode " + signedToken.GetHashCode());
                RevocationInfo[signedToken] = null;
                if (signedToken is CRLToken token)
                {
                    NeededCRLTokens.Add(token);
                }
                else
                {
                    if (signedToken is OCSPRespToken ocpsToken)
                    {
                        NeededOCSPRespTokens.Add(ocpsToken);
                    }
                    else
                    {
                        if (signedToken is CertificateToken token1)
                        {
                            bool found = false;
                            CertificateAndContext newCert = token1.GetCertificateAndContext();
                            foreach (CertificateAndContext c in NeededCertificates)
                            {
                                if (c.Certificate.Equals(newCert.Certificate))
                                {
                                    found = true;
                                    break;
                                }
                            }
                            if (!found)
                            {
                                NeededCertificateTokens.Add(token1);
                            }
                        }
                    }
                }
            }
            else
            {
                logger?.Info("Token was already in list " + signedToken);
            }
        }

        internal virtual void Validate(ISignedToken signedToken, RevocationData data)
        {
            if (!RevocationInfo.ContainsKey(signedToken))
            {
                throw new ArgumentException(signedToken + " must be a key of revocationInfo");
            }

            if (data is null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            RevocationInfo[signedToken] = data;
        }

        /// <summary>
        /// Validate the timestamp
        /// </summary>
        public virtual void ValidateCertificate(
            X509Certificate certificate,
            DateTime validationDate,
            ICertificateSource? optionalSource,
            ICrlSource? optionalCRLSource,
            IOcspSource? optionalOCSPSource,
            IList<CertificateAndContext> usedCerts)
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

            AddNotYetVerifiedToken(certificateTokenFactory(trustedCert ?? new CertificateAndContext(certificate) { RootCause = new List<object?> { certificate } }));

            Validate(
                certificate,
                validationDate,
                optionalSource,
                optionalCRLSource,
                optionalOCSPSource,
                usedCerts);
        }

        /// <summary>
        /// Validate the timestamp
        /// </summary>
        public virtual void ValidateTimestamp(
            TimestampToken timestamp,
            ICertificateSource? optionalSource,
            ICrlSource? optionalCRLSource,
            IOcspSource? optionalOCPSSource,
            IList<CertificateAndContext> usedCerts)
        {
            if (timestamp is null)
            {
                throw new ArgumentNullException(nameof(timestamp));
            }

            AddNotYetVerifiedToken(timestamp);
            Validate(
                timestamp,
                timestamp.GetTimeStamp().TimeStampInfo.GenTime,
                new CompositeCertificateSource(timestamp.GetWrappedCertificateSource(), optionalSource),
                optionalCRLSource,
                optionalOCPSSource,
                usedCerts);
        }

        /// <summary>
        /// Build the validation context for the specific date
        /// </summary>
        public virtual void Validate(
            object rootValidationCause,
            DateTime validationDate,
            ICertificateSource? optionalSource,
            ICrlSource? optionalCRLSource,
            IOcspSource? optionalOCPSSource,
            IList<CertificateAndContext>? usedCerts)
        {
            int previousSize = RevocationInfo.Count;
            int previousVerified = VerifiedTokenCount();
            var signedToken = GetOneNotYetVerifiedToken();
            if (signedToken != null)
            {
                nloglogger?.Trace($"rootValidationCause: {rootValidationCause.GetType()}, signedTokenType: {signedToken.GetType()}, signedToken: {signedToken}");
                // TODO: for certificateToken the source is aia, so put it at position of last resort (will be valuable to rearange composite sources so sources that use network connection will be used at a last time)
                ICertificateSource otherSource = new CompositeCertificateSource(new ListCertificateSource(this.NeededCertificates.Select(x => x.Certificate).ToList()), optionalSource, signedToken.GetWrappedCertificateSource());
                CertificateAndContext? issuer = GetIssuerCertificate(signedToken, otherSource, validationDate);
                RevocationData? data = null;
                if (issuer != null)
                {
                    nloglogger?.Trace($"issuer: {issuer}");
                    var alreadyProcessed = NeededCertificates.FirstOrDefault(x => x.Certificate.Equals(issuer.Certificate));

                    if (alreadyProcessed is null)
                    {
                        nloglogger?.Trace($"NOT already processed");
                        usedCerts?.Add(issuer);
                        issuer.RootCause.Add(rootValidationCause);
                        var certToken = certificateTokenFactory(issuer);
                        AddNotYetVerifiedToken(certToken);
                        if (issuer.Certificate.SubjectDN.Equals(issuer.Certificate.IssuerDN) && issuer.Certificate.IsSignedBy(issuer.Certificate))
                        {
                            ISignedToken trustedToken = certToken;
                            RevocationData noNeedToValidate = new RevocationData();
                            if (issuer.CertificateSource == CertificateSourceType.TRUSTED_LIST)
                            {
                                noNeedToValidate.SetRevocationData(CertificateSourceType.TRUSTED_LIST);
                            }
                            Validate(trustedToken, noNeedToValidate);
                        }
                    }
                    else
                    {
                        nloglogger?.Trace($"already processed");
                        issuer = alreadyProcessed;
                        if (!(usedCerts?.Any(x => x.Certificate.Equals(issuer.Certificate))) ?? false)
                        {
                            usedCerts?.Add(issuer);
                            foreach (var c in GetCertsChain(issuer))
                            {
                                if (!(usedCerts?.Any(x => x.Certificate.Equals(c.Certificate))) ?? false)
                                {
                                    usedCerts?.Add(c);

                                }
                            }
                        }

                        if (rootValidationCause is X509Certificate && !issuer.RootCause.Any(x => x is X509Certificate))
                        {
                            nloglogger?.Trace($"Root cause is not X509Certificate");
                            issuer.RootCause.Add(rootValidationCause);
                            foreach (var c in GetCertsChain(issuer))
                            {
                                nloglogger?.Trace($"Root cause in cert chain, cert: {c}");
                                c.RootCause.Add(rootValidationCause);
                                foreach (var crlt in GetRelatedCRLTokens(c))
                                {
                                    nloglogger?.Trace($"Root cause in cert chain, related crl: {crlt}");
                                    crlt.RootCause.Add(rootValidationCause);
                                }
                                foreach (var crlt in GetRelatedOCSPRespTokens(c))
                                {
                                    nloglogger?.Trace($"Root cause in cert chain, related ocsp: {crlt}");
                                    crlt.RootCause.Add(rootValidationCause);
                                }
                            }
                        }
                    }
                }

                if (signedToken is CertificateToken ct)
                {
                    var certAndContext = ct.GetCertificateAndContext();
                    if (!(usedCerts?.Any(x => x.Certificate.Equals(certAndContext.Certificate))) ?? false)
                    {
                        usedCerts?.Add(certAndContext);
                    }
                    certAndContext.IssuerCertificate = issuer;
                    CertificateStatus? status = GetCertificateValidity(certAndContext, issuer, validationDate, optionalCRLSource, optionalOCPSSource);
                    certAndContext.CertificateStatus = status;
                    data = new RevocationData(signedToken);
                    if (status != null)
                    {
                        data.SetRevocationData(status.StatusSource);
                        if (status.StatusSource is X509Crl crl)
                        {
                            AddNotYetVerifiedToken(new CRLToken(crl, rootValidationCause));
                        }
                        else
                        {
                            if (status.StatusSource is BasicOcspResp resp)
                            {
                                AddNotYetVerifiedToken(new OCSPRespToken(resp, rootValidationCause));
                            }
                        }
                    }
                    else
                    {
                        logger?.Warn("No status for " + signedToken);
                    }
                }
                else
                {
                    if (signedToken is CRLToken || signedToken is OCSPRespToken || signedToken is TimestampToken)
                    {
                        data = new RevocationData(signedToken);
                        data.SetRevocationData(issuer);
                    }
                    else
                    {
                        throw new Exception("Not supported token type " + signedToken.GetType().Name);
                    }
                }

                Validate(signedToken, data);
                logger?.Info(ToString());
                int newSize = RevocationInfo.Count;
                int newVerified = VerifiedTokenCount();
                if (newSize != previousSize || newVerified != previousVerified)
                {
                    Validate(rootValidationCause, validationDate, optionalSource, optionalCRLSource, optionalOCPSSource, usedCerts);
                }
            }
        }

        internal virtual int VerifiedTokenCount()
        {
            int count = 0;
            foreach (var e in RevocationInfo)
            {
                if (e.Value != null)
                {
                    count++;
                }
            }
            return count;
        }

        public override string ToString()
        {
            int count = 0;
            StringBuilder builder = new StringBuilder();
            foreach (var e in RevocationInfo)
            {
                if (e.Value != null)
                {
                    builder.Append(e.Value);
                    count++;
                }
                else
                {
                    builder.Append(e.Key);
                }
                builder.Append(" ");
            }
            return $"ValidationContext contains {RevocationInfo.Count} ISignedToken and {count} of them have been verified. List : {builder.ToString()}";
        }

        private CertificateStatus? GetCertificateValidity(CertificateAndContext cert, CertificateAndContext? potentialIssuer, DateTime validationDate, ICrlSource? optionalCRLSource, IOcspSource? optionalOCSPSource)
        {
            if (optionalCRLSource != null || optionalOCSPSource != null)
            {
                logger?.Info(VerifyWithOfflineServiceMessage);
                var verifier = certificateVerifierFactory(optionalOCSPSource, optionalCRLSource);
                var status = verifier.Check(cert.Certificate, potentialIssuer?.Certificate, validationDate);
                if (status != null)
                {
                    return status;
                }
            }
            logger?.Info(VerifyWithOnlineServiceMessage);
            var onlineVerifier = certificateVerifierFactory(OcspSource, CrlSource);
            return onlineVerifier.Check(cert.Certificate, potentialIssuer?.Certificate, validationDate);
        }

        /// <summary>
        /// Finds the provided certificate's issuer in the context
        /// </summary>
        /// <param>
        /// The certificate whose issuer to find
        /// </param>
        /// <returns>
        /// the issuer's X509Certificate
        /// </returns>
        public virtual CertificateAndContext? GetIssuerCertificateFromThisContext(CertificateAndContext cert) => cert.IssuerCertificate;

        private bool ConcernsCertificate(X509Crl x509crl, CertificateAndContext cert)
        {
            var issuerCertificate = GetIssuerCertificateFromThisContext(cert);
            if (issuerCertificate == null)
            {
                return false;
            }
            else
            {
                return x509crl.IssuerDN.Equals(cert.Certificate.IssuerDN);
            }
        }

        private bool ConcernsCertificate(BasicOcspResp basicOcspResp, CertificateAndContext
             cert)
        {
            var issuerCertificate = GetIssuerCertificateFromThisContext(cert);
            if (issuerCertificate == null)
            {
                return false;
            }
            else
            {
                foreach (SingleResp resp in basicOcspResp.Responses)
                {
                    var certID = resp.GetCertID();
                    CertificateID matchingCertID = new CertificateID(certID.HashAlgOid, issuerCertificate.Certificate, cert.Certificate.SerialNumber);
                    if (certID.EqualsWithDerNull(matchingCertID))
                    {
                        return true;
                    }
                }
                return false;
            }
        }

        /// <summary>
        /// Returns the CRLs in the context which concern the provided certificate.
        /// </summary>
        /// <remarks>
        /// Returns the CRLs in the context which concern the provided certificate. It can happen there are more than one,
        /// even though this is unlikely.
        /// </remarks>
        /// <param>
        /// the X509 certificate
        /// </param>
        /// <returns>
        /// the list of CRLs related to the certificate
        /// </returns>
        public virtual IList<X509Crl> GetRelatedCRLs(CertificateAndContext cert)
        {
            if (cert is null)
            {
                throw new ArgumentNullException(nameof(cert));
            }

            IList<X509Crl> crls = new List<X509Crl>();
            foreach (X509Crl crl in NeededCRL)
            {
                if (ConcernsCertificate(crl, cert))
                {
                    crls.Add(crl);
                }
            }
            return crls;
        }

        public virtual IList<CRLToken> GetRelatedCRLTokens(CertificateAndContext cert)
        {
            if (cert is null)
            {
                throw new ArgumentNullException(nameof(cert));
            }

            var crlTokens = new List<CRLToken>();
            //foreach (var crlToken in NeededCRLTokens)
            //{
            //    var crl = crlToken.GetX509crl();
            //    if (ConcernsCertificate(crl, cert))
            //    {
            //        crlTokens.Add(crlToken);
            //    }
            //}
            //return crlTokens;

            var crls = RevocationInfo
                .Where(x => x.Key is CertificateToken token && token.GetCertificateAndContext().Equals(cert) && x.Value?.GetRevocationData() is X509Crl)
                .Select(x => (x.Value!.GetRevocationData() as X509Crl)).ToList();

            return NeededCRLTokens.Where(x => crls.Contains(x.GetX509crl())).ToList();
        }

        /// <summary>
        /// Returns the OCSP responses in the context which concern the provided certificate.
        /// </summary>
        /// <remarks>
        /// Returns the OCSP responses in the context which concern the provided certificate. It can happen there are more
        /// than one, even though this is unlikely.
        /// </remarks>
        /// <param>
        /// the X509 certificate
        /// </param>
        /// <returns>
        /// the list of OCSP responses related to the certificate
        /// </returns>
        public virtual IList<BasicOcspResp> GetRelatedOCSPResp(CertificateAndContext cert)
        {
            if (cert is null)
            {
                throw new ArgumentNullException(nameof(cert));
            }

            IList<BasicOcspResp> ocspresps = new List<BasicOcspResp>();
            foreach (BasicOcspResp ocspresp in NeededOCSPResp)
            {
                if (ConcernsCertificate(ocspresp, cert))
                {
                    ocspresps.Add(ocspresp);
                }
            }
            return ocspresps;
        }

        public virtual IList<OCSPRespToken> GetRelatedOCSPRespTokens(CertificateAndContext cert)
        {
            if (cert is null)
            {
                throw new ArgumentNullException(nameof(cert));
            }

            var ocspresps = new List<OCSPRespToken>();
            foreach (var ocsprespToken in NeededOCSPRespTokens)
            {
                var ocspresp = ocsprespToken.GetOcspResp();
                if (ConcernsCertificate(ocspresp, cert))
                {
                    ocspresps.Add(ocsprespToken);
                }
            }
            return ocspresps;
        }

        public virtual CertificateStatus? GetCertificateStatusFromContext(CertificateAndContext cert)
        {
            if (cert is null)
            {
                throw new ArgumentNullException(nameof(cert));
            }

            if (cert.CertificateSource == CertificateSourceType.TRUSTED_LIST && cert.Certificate.IsSignedBy(cert.Certificate))
            {
                CertificateStatus status = new CertificateStatus
                {
                    Validity = CertificateValidity.VALID,
                    StatusSourceType = ValidatorSourceType.TRUSTED_LIST,
                    Certificate = cert.Certificate
                };
                return status;
            }
            var issuer = GetIssuerCertificateFromThisContext(cert);
            if (issuer == null)
            {
                return null;
            }
            IOcspSource ocspSource = new ListOCSPSource(NeededOCSPResp);
            ICrlSource crlSource = new ListCRLSource(NeededCRL);
            var verifier = certificateVerifierFactory(ocspSource, crlSource);
            return verifier.Check(cert.Certificate, issuer.Certificate, ValidationDate);
        }

        /// <summary>
        /// Retrieve the parent from the trusted list
        /// </summary>
        public virtual CertificateAndContext? GetParentFromTrustedList(CertificateAndContext ctx)
        {
            var parent = ctx;
            while ((parent = GetIssuerCertificateFromThisContext(parent)) != null)
            {
                if (parent.CertificateSource == CertificateSourceType.TRUSTED_LIST && parent.Certificate.IsSignedBy(parent.Certificate))
                {
                    logger?.Info("Parent from TrustedList found " + parent);
                    return parent;
                }
            }
            logger?.Warn("No issuer in the TrustedList for this certificate. The parent found is " + parent);
            return null;
        }

        /// <summary>
        /// Return the ServiceInfo of the parent (in the Trusted List) of the certificate
        /// </summary>
        public virtual ServiceInfo? GetRelevantServiceInfo()
        {
            if (Certificate is null)
            {
                return null;
            }

            var cert = new CertificateAndContext(Certificate);
            var parent = GetParentFromTrustedList(cert);
            if (parent == null)
            {
                return null;
            }
            else
            {
                var info = parent.Context as ServiceInfo;
                return info;
            }
        }

        /// <summary>
        /// Return the qualifications statement for the signing certificate
        /// </summary>
        public virtual IList<string>? GetQualificationStatement()
        {
            var info = GetRelevantServiceInfo();
            logger?.Info("Service Information " + info);
            if (info == null)
            {
                return null;
            }
            else
            {
                if (Certificate is null)
                {
                    return null;
                }

                return info.GetQualifiers(new CertificateAndContext(Certificate));
            }
        }

        public SignatureValidationResult GetOcspStatus(BasicOcspResp resp) => GetCertsResult(GetCertsChain(resp));

        public SignatureValidationResult GetCrlStatus(CRLToken crlToken) => GetCertsResult(GetCertsChain(crlToken.GetX509crl()));


        private SignatureValidationResult GetCertsResult(IEnumerable<CertificateAndContext> certificateAndContexts)
        {
            var result = new SignatureValidationResult();
            var statuses = certificateAndContexts.Select(
                x => x.CertificateStatus == null ?
                    GetRevocationData(x) == null && !(x.CertificateSource == CertificateSourceType.TRUSTED_LIST && x.Certificate.IsSignedBy(x.Certificate)) ?
                        CertificateValidity.UNKNOWN
                        : CertificateValidity.VALID
                    : x.CertificateStatus.Validity).ToArray();

            if (statuses.Any(x => x == CertificateValidity.REVOKED))
            {
                result.SetStatus(SignatureValidationResult.ResultStatus.INVALID, string.Empty);
            }
            else if (statuses.Any(x => x == CertificateValidity.UNKNOWN))
            {
                result.SetStatus(SignatureValidationResult.ResultStatus.UNDETERMINED, string.Empty);
            }
            else
            {
                result.SetStatus(SignatureValidationResult.ResultStatus.VALID, string.Empty);
            }

            return result;
        }

        private List<CertificateAndContext> GetCertsChain(BasicOcspResp resp, List<CertificateAndContext>? certSet = null)
        {
            var certSetLocal = certSet ?? new List<CertificateAndContext>();

            if (resp is null)
            {
                return certSetLocal;
            }

            if (RevocationInfo.Where(x => (x.Key as OCSPRespToken)?.GetOcspResp() == resp).FirstOrDefault().Value?.GetRevocationData() is CertificateAndContext certAndContext)
            {
                certSetLocal = certSetLocal.Union(GetCertsChain(certAndContext, certSetLocal)).ToList();
            }

            return certSetLocal;
        }

        private List<CertificateAndContext> GetCertsChain(X509Crl crl, List<CertificateAndContext>? certSet = null)
        {
            var certSetLocal = certSet ?? new List<CertificateAndContext>();

            if (crl is null)
            {
                return certSetLocal;
            }

            var certAndContext = RevocationInfo.Where(x => (x.Key as CRLToken)?.GetX509crl() == crl).FirstOrDefault().Value?.GetRevocationData() as CertificateAndContext;

            if (certSetLocal != null && certAndContext != null)
            {
                certSetLocal = certSetLocal.Union(GetCertsChain(certAndContext, certSetLocal)).ToList();
            }

            return certSetLocal!;
        }

        public List<CertificateAndContext> GetCertsChain(CertificateAndContext certificateAndContext, List<CertificateAndContext>? certSet = null)
        {
            var certSetLocal = certSet ?? new List<CertificateAndContext>();

            if (certificateAndContext is null || certSetLocal.Exists(x => x == certificateAndContext))
            {
                return certSetLocal;
            }

            certSetLocal.Add(certificateAndContext);
            var revocationData = GetRevocationData(certificateAndContext);

            if (revocationData is BasicOcspResp ocspResp)
            {
                certSetLocal = certSetLocal.Union(GetCertsChain(ocspResp, certSetLocal)).ToList();
            }
            else if (revocationData is X509Crl crl)
            {
                certSetLocal = certSetLocal.Union(GetCertsChain(crl, certSetLocal)).ToList();
            }

            if (certificateAndContext.IssuerCertificate != null)
            {
                certSetLocal = certSetLocal.Union(GetCertsChain(certificateAndContext.IssuerCertificate, certSetLocal)).ToList();
            }

            return certSetLocal;
        }

        private object? GetRevocationData(CertificateAndContext certificateAndContext)
        {
            return RevocationInfo.FirstOrDefault(x => (x.Key as CertificateToken)?.GetCertificateAndContext() == certificateAndContext).Value?.GetRevocationData();
        }
    }
}
