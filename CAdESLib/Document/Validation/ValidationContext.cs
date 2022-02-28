using CAdESLib.Helpers;
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
        X509Certificate Certificate { get; }
        IList<X509Crl> NeededCRL { get; }
        IList<CRLToken> NeededCRLTokens { get; }
        IList<CertificateAndContext> NeededCertificates { get; }
        DateTime ValidationDate { get; set; }
        ICrlSource CrlSource { get; }
        IOcspSource OcspSource { get; }
        ICertificateSource TrustedListCertificatesSource { get; }
        IDictionary<ISignedToken, RevocationData> RevocationInfo { get; }
        void ValidateCertificate(X509Certificate certificate, DateTime validationDate, ICertificateSource optionalSource, ICrlSource optionalCRLSource, IOcspSource optionalOCSPSource, IList<CertificateAndContext> usedCerts);
        IList<X509Crl> GetRelatedCRLs(CertificateAndContext cert);
        IList<CRLToken> GetRelatedCRLTokens(CertificateAndContext cert);
        IList<BasicOcspResp> GetRelatedOCSPResp(CertificateAndContext cert);
        IList<OCSPRespToken> GetRelatedOCSPRespTokens(CertificateAndContext cert);
        void ValidateTimestamp(TimestampToken timestamp, ICertificateSource optionalSource, ICrlSource optionalCRLSource, IOcspSource optionalOCPSSource, IList<CertificateAndContext> usedCerts);
        CertificateAndContext GetParentFromTrustedList(CertificateAndContext ctx);
        IList<string> GetQualificationStatement();
        ServiceInfo GetRelevantServiceInfo();
        CertificateStatus GetCertificateStatusFromContext(CertificateAndContext cert);
        SignatureValidationResult GetOcspStatus(BasicOcspResp x);
        SignatureValidationResult GetCrlStatus(CRLToken crlToken);
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
        //private static readonly Logger logger = LogManager.GetCurrentClassLogger();
        private readonly ICAdESLogger logger;


        public IList<BasicOcspResp> NeededOCSPResp => NeededOCSPRespTokens.Select(x => x.GetOcspResp()).ToList();
        public IList<OCSPRespToken> NeededOCSPRespTokens { get; } = new List<OCSPRespToken>();
        public X509Certificate Certificate { get; }
        public IList<X509Crl> NeededCRL => NeededCRLTokens.Select(x => x.GetX509crl()).ToList();
        public IList<CRLToken> NeededCRLTokens { get; } = new List<CRLToken>();
        public IList<CertificateAndContext> NeededCertificates { get; } = new List<CertificateAndContext>();
        public DateTime ValidationDate { get; set; }

        private readonly Func<IOcspSource, ICrlSource, ICertificateStatusVerifier> certificateVerifierFactory;

        private readonly Func<CertificateAndContext, CertificateToken> certificateTokenFactory;

        public ICrlSource CrlSource { get; set; }
        public IOcspSource OcspSource { get; set; }
        public ICertificateSource TrustedListCertificatesSource { get; set; }
        public IDictionary<ISignedToken, RevocationData> RevocationInfo { get; } = new Dictionary<ISignedToken, RevocationData>();
        //DateTime IValidationContext.ValidationDate { get; set; }


        /// <summary>
        /// The default constructor for ValidationContextV2.
        /// </summary>
        /// <param>
        /// The certificate that will be validated.
        /// </param>
        public ValidationContext(X509Certificate certificate, DateTime validationDate, ICAdESLogger cadesLogger, IOcspSource ocspSource, ICrlSource crlSource, ICertificateSource certificateSource, Func<IOcspSource, ICrlSource, ICertificateStatusVerifier> certificateVerifierFactory, Func<CertificateAndContext, CertificateToken> certificateTokenFactory)
        {
            this.certificateTokenFactory = certificateTokenFactory;
            OcspSource = ocspSource;
            CrlSource = crlSource;
            TrustedListCertificatesSource = certificateSource;
            logger = cadesLogger;
            if (certificate != null)
            {
                logger?.Info("New context for " + certificate.SubjectDN);
                //var trustedCert = TrustedListCertificatesSource?.GetCertificateBySubjectName(certificate.SubjectDN)?.FirstOrDefault();
                Certificate = certificate;
                //AddNotYetVerifiedToken(certificateTokenFactory(trustedCert ?? new CertificateAndContext(certificate)));
            }
            ValidationDate = validationDate;
            this.certificateVerifierFactory = certificateVerifierFactory;
        }

        internal virtual ISignedToken GetOneNotYetVerifiedToken()
        {
            foreach (KeyValuePair<ISignedToken, RevocationData> e in RevocationInfo)
            {
                if (e.Value == null)
                {
                    logger?.Info("=== Get token to validate " + e.Key);
                    return e.Key;
                }
            }
            return null;
        }

        internal virtual CertificateAndContext GetIssuerCertificate(ISignedToken signedToken, ICertificateSource optionalSource, DateTime validationDate)
        {
            if (signedToken.GetSignerSubjectName() == null)
            {
                return null;
            }
            var list = new CompositeCertificateSource(TrustedListCertificatesSource, optionalSource).GetCertificateBySubjectName(signedToken.GetSignerSubjectName());
            if (list != null)
            {
                foreach (CertificateAndContext cert in list)
                {
                    logger?.Info(cert.ToString());
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
                        if (cert.CertificateSource == CertificateSourceType.TRUSTED_LIST && cert.Context != null)
                        {
                            ServiceInfo info = (ServiceInfo)cert.Context;
                            if (info.StatusStartingDateAtReferenceTime != null && validationDate.CompareTo( //jbonilla Before
                                info.StatusStartingDateAtReferenceTime) < 0)
                            {
                                logger?.Info(WasNotValidTSLMessage);
                                continue;
                            }
                            else
                            {
                                if (info.StatusEndingDateAtReferenceTime != null && validationDate.CompareTo(info //jbonilla After
                                    .StatusEndingDateAtReferenceTime) > 0)
                                {
                                    logger?.Info(WasNotValidTSLMessage);
                                    continue;
                                }
                            }
                        }
                    }
                    if (signedToken.IsSignedBy(cert.Certificate))
                    {
                        return cert;
                    }
                }
            }
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
                                NeededCertificates.Add(newCert);
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
        public virtual void ValidateCertificate(X509Certificate certificate, DateTime validationDate, ICertificateSource optionalSource, ICrlSource optionalCRLSource, IOcspSource optionalOCSPSource, IList<CertificateAndContext> usedCerts)
        {
            if (certificate is null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            var trustedCert = TrustedListCertificatesSource?.GetCertificateBySubjectName(certificate.SubjectDN)?.FirstOrDefault();
            AddNotYetVerifiedToken(certificateTokenFactory(trustedCert ?? new CertificateAndContext(certificate)));

            Validate(
                validationDate,
                optionalSource,
                optionalCRLSource,
                optionalOCSPSource,
                usedCerts);
        }

        /// <summary>
        /// Validate the timestamp
        /// </summary>
        public virtual void ValidateTimestamp(TimestampToken timestamp, ICertificateSource optionalSource, ICrlSource optionalCRLSource, IOcspSource optionalOCPSSource, IList<CertificateAndContext> usedCerts)
        {
            if (timestamp is null)
            {
                throw new ArgumentNullException(nameof(timestamp));
            }

            AddNotYetVerifiedToken(timestamp);
            Validate(
                timestamp.GetTimeStamp().TimeStampInfo.GenTime,
                new CompositeCertificateSource(timestamp.GetWrappedCertificateSource(), optionalSource),
                optionalCRLSource,
                optionalOCPSSource,
                usedCerts);
        }

        /// <summary>
        /// Build the validation context for the specific date
        /// </summary>
        public virtual void Validate(DateTime validationDate, ICertificateSource optionalSource, ICrlSource optionalCRLSource, IOcspSource optionalOCPSSource, IList<CertificateAndContext> usedCerts)
        {
            int previousSize = RevocationInfo.Count;
            int previousVerified = VerifiedTokenCount();
            ISignedToken signedToken = GetOneNotYetVerifiedToken();
            if (signedToken != null)
            {
                ICertificateSource otherSource = new CompositeCertificateSource(signedToken.GetWrappedCertificateSource(), optionalSource);
                CertificateAndContext issuer = GetIssuerCertificate(signedToken, otherSource, validationDate);
                RevocationData data = null;
                if (issuer == null)
                {
                    logger?.Warn("Don't found any issuer for token " + signedToken);
                    //data = new RevocationData(signedToken);
                }
                else
                {
                    var alreadyProcessed = NeededCertificates.FirstOrDefault(x => x.Certificate.Equals(issuer.Certificate));

                    if (alreadyProcessed is null)
                    {
                        usedCerts?.Add(issuer);
                        AddNotYetVerifiedToken(certificateTokenFactory(issuer));
                        if (issuer.Certificate.SubjectDN.Equals(issuer.Certificate.IssuerDN))
                        {
                            ISignedToken trustedToken = certificateTokenFactory(issuer);
                            RevocationData noNeedToValidate = new RevocationData();
                            if (issuer.CertificateSource == CertificateSourceType.TRUSTED_LIST)
                            {
                                noNeedToValidate.SetRevocationData(CertificateSourceType.TRUSTED_LIST);
                            }
                            Validate(trustedToken, noNeedToValidate);
                        }
                        else if (issuer.CertificateSource == CertificateSourceType.TRUSTED_LIST)
                        {
                            ISignedToken trustedToken = certificateTokenFactory(issuer);
                            RevocationData noNeedToValidate = new RevocationData();
                            noNeedToValidate.SetRevocationData(CertificateSourceType.TRUSTED_LIST);
                            Validate(trustedToken, noNeedToValidate);
                        }
                    }
                    else
                    {
                        issuer = alreadyProcessed;
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
                    CertificateStatus status = GetCertificateValidity(certAndContext, issuer, validationDate, optionalCRLSource, optionalOCPSSource);
                    certAndContext.CertificateStatus = status;
                    data = new RevocationData(signedToken);
                    if (status != null)
                    {
                        data.SetRevocationData(status.StatusSource);
                        if (status.StatusSource is X509Crl crl)
                        {
                            AddNotYetVerifiedToken(new CRLToken(crl));
                        }
                        else
                        {
                            if (status.StatusSource is BasicOcspResp resp)
                            {
                                AddNotYetVerifiedToken(new OCSPRespToken(resp));
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
                    Validate(validationDate, otherSource, optionalCRLSource, optionalOCPSSource, usedCerts);
                }
            }
        }

        internal virtual int VerifiedTokenCount()
        {
            int count = 0;
            foreach (KeyValuePair<ISignedToken, RevocationData> e in RevocationInfo)
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
            foreach (KeyValuePair<ISignedToken, RevocationData> e in RevocationInfo)
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
            return "ValidationContext contains " + RevocationInfo.Count + " ISignedToken and "
                 + count + " of them have been verified. List : " + builder.ToString();
        }

        private CertificateStatus GetCertificateValidity(CertificateAndContext cert, CertificateAndContext potentialIssuer, DateTime validationDate, ICrlSource optionalCRLSource, IOcspSource optionalOCSPSource)
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
        public virtual CertificateAndContext GetIssuerCertificateFromThisContext(CertificateAndContext cert) => cert.IssuerCertificate;

        private bool ConcernsCertificate(X509Crl x509crl, CertificateAndContext cert)
        {
            return x509crl.IssuerDN.Equals(cert.Certificate.IssuerDN);
        }

        private bool ConcernsCertificate(BasicOcspResp basicOcspResp, CertificateAndContext
             cert)
        {
            CertificateAndContext issuerCertificate = GetIssuerCertificateFromThisContext(cert);
            if (issuerCertificate == null)
            {
                return false;
            }
            else
            {
                //try
                //{
                CertificateID matchingCertID = new CertificateID(CertificateID.HashSha1, issuerCertificate
                    .Certificate, cert.Certificate.SerialNumber);
                foreach (SingleResp resp in basicOcspResp.Responses)
                {
                    if (resp.GetCertID().Equals(matchingCertID))
                    {
                        return true;
                    }
                }
                return false;
                //}
                //catch (OcspException ex)
                //{
                //    throw new RuntimeException(ex);
                //}
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
                .Where(x => x.Key is CertificateToken token && token.GetCertificateAndContext().Equals(cert) && x.Value.GetRevocationData() is X509Crl)
                .Select(x => (x.Value.GetRevocationData() as X509Crl)).ToList();

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

        public virtual CertificateStatus GetCertificateStatusFromContext(CertificateAndContext cert)
        {
            if (cert is null)
            {
                throw new ArgumentNullException(nameof(cert));
            }

            if (cert.CertificateSource == CertificateSourceType.TRUSTED_LIST)
            {
                CertificateStatus status = new CertificateStatus
                {
                    Validity = CertificateValidity.VALID,
                    StatusSourceType = ValidatorSourceType.TRUSTED_LIST,
                    Certificate = cert.Certificate
                };
                return status;
            }
            CertificateAndContext issuer = GetIssuerCertificateFromThisContext(cert);
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
        public virtual CertificateAndContext GetParentFromTrustedList(CertificateAndContext ctx)
        {
            CertificateAndContext parent = ctx;
            while ((parent = GetIssuerCertificateFromThisContext(parent)) != null)
            {
                if (parent.CertificateSource == CertificateSourceType.TRUSTED_LIST)
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
        public virtual ServiceInfo GetRelevantServiceInfo()
        {
            CertificateAndContext cert = new CertificateAndContext(Certificate);
            CertificateAndContext parent = GetParentFromTrustedList(cert);
            if (parent == null)
            {
                return null;
            }
            else
            {
                ServiceInfo info = (ServiceInfo)parent.Context;
                return info;
            }
        }

        /// <summary>
        /// Return the qualifications statement for the signing certificate
        /// </summary>
        public virtual IList<string> GetQualificationStatement()
        {
            ServiceInfo info = GetRelevantServiceInfo();
            logger?.Info("Service Information " + info);
            if (info == null)
            {
                return null;
            }
            else
            {
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
                    GetRevocationData(x) == null && x.CertificateSource != CertificateSourceType.TRUSTED_LIST ?
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

        private IEnumerable<CertificateAndContext> GetCertsChain(BasicOcspResp resp)
        {
            IEnumerable<CertificateAndContext> certSet = new List<CertificateAndContext>();

            if (resp is null)
            {
                return certSet;
            }

            if (RevocationInfo.Where(x => (x.Key as OCSPRespToken)?.GetOcspResp() == resp).FirstOrDefault().Value?.GetRevocationData() is CertificateAndContext certAndContext)
            {
                certSet = certSet.Union(GetCertsChain(certAndContext));
            }

            return certSet;
        }

        private IEnumerable<CertificateAndContext> GetCertsChain(X509Crl crl)
        {
            IEnumerable<CertificateAndContext> certSet = new List<CertificateAndContext>();

            if (crl is null)
            {
                return certSet;
            }

            var certAndContext = RevocationInfo.Where(x => (x.Key as CRLToken)?.GetX509crl() == crl).FirstOrDefault().Value?.GetRevocationData() as CertificateAndContext;

            if (certSet != null)
            {
                certSet = certSet = certSet.Union(GetCertsChain(certAndContext));
            }

            return certSet;
        }

        private IEnumerable<CertificateAndContext> GetCertsChain(CertificateAndContext certificateAndContext)
        {
            var certSet = new List<CertificateAndContext>();

            if (certificateAndContext is null)
            {
                return certSet;
            }

            certSet.Add(certificateAndContext);
            var revocationData = GetRevocationData(certificateAndContext);

            if (revocationData is BasicOcspResp)
            {
                certSet = certSet.Union(GetCertsChain(revocationData as BasicOcspResp)).ToList();
            }
            else if (revocationData is X509Crl)
            {
                certSet = certSet.Union(GetCertsChain(revocationData as X509Crl)).ToList();
            }

            certSet = certSet.Union(GetCertsChain(certificateAndContext.IssuerCertificate)).ToList();

            return certSet;
        }

        private object GetRevocationData(CertificateAndContext certificateAndContext)
        {
            return RevocationInfo.FirstOrDefault(x => (x.Key as CertificateToken)?.GetCertificateAndContext() == certificateAndContext).Value?.GetRevocationData();
        }
    }
}
