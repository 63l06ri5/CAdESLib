using System.Collections.Generic;
using CAdESLib.Helpers;
using System.Linq;
using System;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using NLog;
using System.Text;

namespace CAdESLib.Document.Validation
{
    public class RevocationInfo
    {
        private static readonly Logger nloglogger = LogManager.GetCurrentClassLogger();

        HashSet<RevocationData> Data { get; } = new HashSet<RevocationData>();
        public HashSet<CRLToken> NeededCRLTokens { get; } = new HashSet<CRLToken>();
        public HashSet<OCSPRespToken> NeededOCSPRespTokens { get; } = new HashSet<OCSPRespToken>();
        public HashSet<CertificateToken> NeededCertificateTokens { get; } = new HashSet<CertificateToken>();

        public int Count => Data.Count;

        public bool RevocationDataOutdated(CertificateAndContext certContext, DateTime startDate, DateTime endDate)
        {
            nloglogger.Trace($"RevocationDataOutdated BEGIN, cert={certContext.Certificate.SubjectDN}, startDate={startDate}, endDate={endDate}");
            var revocationData = GetRevocationData(certContext, startDate, endDate);
            return RevocationDataOutdatedInternal(revocationData, startDate, endDate);
        }

        private static bool RevocationDataOutdatedInternal(StatusSource? revocationData, DateTime startDate, DateTime endDate)
        {
            nloglogger.Trace($"RevocationDataOutdated BEGIN, startDate={startDate}, endDate={endDate}");
            nloglogger.Trace("revdata result cert: " + (revocationData?.Source?.GetType().ToString() ?? "null"));
            if (revocationData is null)
            {
                return true;
            }
            else if (revocationData.Resp is BasicOcspResp ocspResp)
            {
                var firstResponse = ocspResp.Responses.FirstOrDefault();
                nloglogger.Trace($"OCSP candidate found. thisUpdate={firstResponse?.ThisUpdate}, nextUpdate={firstResponse?.NextUpdate?.Value}");
                if (!ocspResp.IsValid(startDate, endDate))
                {
                    nloglogger.Trace("outdated OCSP found");
                    return true;
                }

            }
            else if (revocationData.Crl is X509Crl crl)
            {
                nloglogger.Trace($"CRL candidate found. thisUpdate={crl.ThisUpdate}, nextUpdate={crl.NextUpdate?.Value}");
                if (!crl.IsValid(startDate, endDate))
                {
                    nloglogger.Trace("outdated CRL found");
                    return true;
                }
            }

            nloglogger.Trace("RevocationDataOutdated END");
            return false;
        }

        public StatusSource? GetRevocationData(CertificateAndContext certificateAndContext, DateTime startDate, DateTime endDate)
        {
            nloglogger.Trace($"GetRevocationData startDate={startDate}, endDate={endDate}, certSource={certificateAndContext.CertificateSource}, cert: {certificateAndContext.Certificate.SubjectDN},");

            var revInfo = Data
                .Where(
                    x =>
                        ((x.TargetToken as CertificateToken)?.CertificateAndContext?.Equals(certificateAndContext) ?? false)
                        && x.RevocationDataAsStatusSource is not null)
                .Select(x => x.RevocationDataAsStatusSource!);

            var result = revInfo.FirstOrDefault(x => x.IsValidForTime(startDate, endDate));

            nloglogger.Trace("result: " + (result?.ToString() ?? "none"));

            return result;
        }

        public RevocationData AddNotYetVerifiedToken(
                ISignedToken signedToken,
                ICAdESLogger cadesLogger
        )
        {
            cadesLogger.Info("New token to validate " + signedToken);
            var data = new RevocationData(signedToken);
            Data.Add(data);
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
                        CertificateAndContext newCert = token1.CertificateAndContext;
                        foreach (var c in NeededCertificateTokens)
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
            return data;
        }

        public int VerifiedTokenCount => Data.Count(x => !x.Processed);

        public RevocationData? GetOneNotYetVerifiedToken(ICAdESLogger cadesLogger)
        {
            var result = Data.FirstOrDefault(x => !x.Processed);
            cadesLogger.Info("=== Get token to validate " + result);
            return result;
        }

        public IList<CRLToken> GetRelatedCRLTokens(
                CertificateAndContext cert,
                DateTime startDate,
                DateTime endDate,
                bool returnNotValidIfEmpty = false)
        {
            nloglogger.Trace($"GetRelatedCRLTokens startDate={startDate}, endDate={endDate}, cert=" + cert?.Certificate.SubjectDN);
            if (cert is null)
            {
                throw new ArgumentNullException(nameof(cert));
            }

            var crlTokens = new List<CRLToken>();

            IEnumerable<X509Crl?> crls;
            var tmpcrls = Data
                .Where(x =>
                        x.TargetToken is CertificateToken token &&
                        token.CertificateAndContext.Equals(cert)
                      );
            crls = tmpcrls.Select(x =>
                    x.GetRevocationDataStatusFor(startDate, endDate)?.Crl);
            crls = crls.Where(x => x is not null);
            if (returnNotValidIfEmpty && !crls.Any())
            {
                crls = tmpcrls.Select(x => x.RevocationDataAsStatusSource?.Crl).Where(x => x is not null);
            }

            return NeededCRLTokens.Where(x => crls.Contains(x.Crl)).ToList();
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
        public IList<BasicOcspResp> GetRelatedOCSPResp(CertificateAndContext cert, DateTime startDate, DateTime endDate)
        {
            if (cert is null)
            {
                throw new ArgumentNullException(nameof(cert));
            }

            IList<BasicOcspResp> ocspresps = new List<BasicOcspResp>();
            foreach (var token in NeededOCSPRespTokens)
            {
                var ocspresp = token.OcspResp;
                if (ConcernsCertificateByCertIssuer(ocspresp, cert))
                {
                    if (ocspresp.IsValid(startDate, endDate))
                    {
                        ocspresps.Add(ocspresp);
                    }
                }
            }
            return ocspresps;
        }

        private static bool ConcernsCertificateByCertIssuer(X509Crl x509crl, CertificateAndContext cert)
        {
            var issuerCertificate = cert.IssuerCertificate;
            if (issuerCertificate == null)
            {
                return false;
            }
            else
            {
                return x509crl.IssuerDN.Equals(cert.Certificate.IssuerDN);
            }
        }

        private static bool ConcernsCertificateByCertIssuer(BasicOcspResp basicOcspResp, CertificateAndContext cert)
        {
            var issuerCertificate = cert.IssuerCertificate;
            nloglogger.Trace("ConcernsCertificateByCertIssuer " + issuerCertificate?.Certificate.SubjectDN);
            return ConcernsCertificate(basicOcspResp, cert, issuerCertificate);
        }
        private static bool ConcernsCertificate(BasicOcspResp basicOcspResp, CertificateAndContext? cert, CertificateAndContext? issuerCert)
        {
            if (cert is null || issuerCert is null)
            {
                return false;
            }
            else
            {
                foreach (SingleResp resp in basicOcspResp.Responses)
                {
                    var certID = resp.GetCertID();
                    CertificateID matchingCertID = new CertificateID(certID.HashAlgOid, issuerCert.Certificate, cert.Certificate.SerialNumber);
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
        public virtual IList<X509Crl> GetRelatedCRLs(CertificateAndContext cert, DateTime startDate, DateTime endDate)
        {
            if (cert is null)
            {
                throw new ArgumentNullException(nameof(cert));
            }

            IList<X509Crl> crls = new List<X509Crl>();
            foreach (var token in NeededCRLTokens)
            {
                var crl = token.Crl;
                if (ConcernsCertificateByCertIssuer(crl, cert))
                {
                    if (crl.IsValid(startDate, endDate))
                    {
                        crls.Add(crl);
                    }
                }
            }
            return crls;
        }

        public List<CertificateAndContext> GetCertsChain(
                X509Certificate certificate,
                DateTime startDate,
                DateTime endDate,
                List<CertificateAndContext>? certSet = null)
        {
            var cert = NeededCertificateTokens.FirstOrDefault(x => x.Certificate.Equals(certificate))?.CertificateAndContext;
            if (cert is null)
            {
                return new List<CertificateAndContext>();
            }

            return GetCertsChain(cert, startDate, endDate, certSet);
        }

        public List<CertificateAndContext> GetCertsChain(
                CertificateAndContext certificateAndContext,
                DateTime startDate,
                DateTime endDate,
                List<CertificateAndContext>? certSet = null)
        {
            var certSetLocal = certSet ?? new List<CertificateAndContext>();

            if (certificateAndContext is null || certSetLocal.Exists(x => x == certificateAndContext))
            {
                return certSetLocal;
            }

            certSetLocal.Add(certificateAndContext);
            var revocationData = GetRevocationData(certificateAndContext, startDate, endDate);

            if (revocationData?.Resp is BasicOcspResp ocspResp)
            {
                certSetLocal = certSetLocal.Union(GetCertsChain(ocspResp, startDate, endDate, certSetLocal)).ToList();
            }
            else if (revocationData?.Crl is X509Crl crl)
            {
                certSetLocal = certSetLocal.Union(GetCertsChain(crl, startDate, endDate, certSetLocal)).ToList();
            }

            if (certificateAndContext.IssuerCertificate != null)
            {
                certSetLocal = certSetLocal.Union(GetCertsChain(certificateAndContext.IssuerCertificate, startDate, endDate, certSetLocal)).ToList();
            }

            return certSetLocal;
        }


        public List<CertificateAndContext> GetCertsChain(
                BasicOcspResp resp,
                DateTime startDate,
                DateTime endDate,
                List<CertificateAndContext>? certSet = null)
        {
            var certSetLocal = certSet ?? new List<CertificateAndContext>();

            if (resp is null)
            {
                return certSetLocal;
            }

            if (Data.Where(x => (x.TargetToken as OCSPRespToken)?.OcspResp == resp)
                    .FirstOrDefault()?.RevocationDataAsCertificate is CertificateAndContext certAndContext)
            {
                certSetLocal = certSetLocal.Union(GetCertsChain(certAndContext, startDate, endDate, certSetLocal)).ToList();
            }

            return certSetLocal;
        }

        public List<CertificateAndContext> GetCertsChain(
                X509Crl crl,
                DateTime startDate,
                DateTime endDate,
                List<CertificateAndContext>? certSet = null)
        {
            var certSetLocal = certSet ?? new List<CertificateAndContext>();

            if (crl is null)
            {
                return certSetLocal;
            }

            var certAndContext = Data.Where(x => (x.TargetToken as CRLToken)?.Crl == crl)
                .FirstOrDefault()?.RevocationDataAsCertificate;

            if (certSetLocal != null && certAndContext != null)
            {
                certSetLocal = certSetLocal.Union(GetCertsChain(certAndContext, startDate, endDate, certSetLocal)).ToList();
            }

            return certSetLocal!;
        }

        public SignatureValidationResult GetOcspStatus(
                BasicOcspResp resp,
                DateTime startDate,
                DateTime endDate) => GetCertsResult(GetCertsChain(resp, startDate, endDate), startDate, endDate);

        public SignatureValidationResult GetCrlStatus(
                CRLToken crlToken,
                DateTime startDate,
                DateTime endDate) => GetCertsResult(GetCertsChain(crlToken.Crl, startDate, endDate), startDate, endDate);

        private CertificateStatus? GetCertificateStatusAtTime(List<CertificateVerification> certificateStatuses, DateTime startDate, DateTime endDate)
        {
            certificateStatuses.Sort((x, y) => x.CertificateStatus.CertificateStatus.StartDate.CompareTo(y.CertificateStatus.CertificateStatus.StartDate));
            return certificateStatuses.LastOrDefault(x => x.CertificateStatus.CertificateStatus.IsValidForTime(startDate, endDate))?.CertificateStatus.CertificateStatus;
        }

        private SignatureValidationResult GetCertsResult(
                IEnumerable<CertificateAndContext> certificateAndContexts,
                DateTime startDate,
                DateTime endDate)
        {
            nloglogger.Trace($"GetCertsResult. startDate={startDate}, endDate={endDate}");
            var result = new SignatureValidationResult();
            var statuses = certificateAndContexts.Select(
                x => x.CertificateVerifications.Count == 0 ?
                    GetRevocationData(x, startDate, endDate) == null && !(x.CertificateSource == CertificateSourceType.TRUSTED_LIST && x.Certificate.IsSignedBy(x.Certificate)) ?
                        CertificateValidity.UNKNOWN
                        : CertificateValidity.VALID
                    : GetCertificateStatusAtTime(x.CertificateVerifications, startDate, endDate)?.Validity).ToArray();

            if (statuses.Any(x => x == CertificateValidity.REVOKED))
            {
                result.SetStatus(SignatureValidationResult.ResultStatus.INVALID, string.Empty);
            }
            else if (statuses.Any(x => x is null || x == CertificateValidity.UNKNOWN))
            {
                nloglogger.Trace("undetermined getcertsresult");
                for (int i = 0; i < certificateAndContexts.Count(); i++)
                {
                    var cert = certificateAndContexts.ElementAt(i);
                    nloglogger.Trace($"status={statuses[i]} verifCount={cert.CertificateVerifications.Count}, subjectDN={cert.Certificate.SubjectDN}");
                    nloglogger.Trace($"verifs={string.Join(", ", cert.CertificateVerifications.Select(x => x.CertificateStatus.CertificateStatus.StatusSource))}");
                }

                result.SetStatus(SignatureValidationResult.ResultStatus.UNDETERMINED, string.Empty);
            }
            else
            {
                result.SetStatus(SignatureValidationResult.ResultStatus.VALID, string.Empty);
            }

            return result;
        }

        public IList<OCSPRespToken> GetRelatedOCSPRespTokens(
                CertificateAndContext cert,
                DateTime startDate,
                DateTime endDate,
                bool returnNotValidIfEmpty = false
                )
        {
            nloglogger.Trace("GetRelatedOCSPRespTokens");
            if (cert is null)
            {
                throw new ArgumentNullException(nameof(cert));
            }

            var ocspresps = new List<OCSPRespToken>();
            var ocsprespsNotValid = new List<OCSPRespToken>();
            foreach (var ocsprespToken in NeededOCSPRespTokens)
            {
                var ocspresp = ocsprespToken.OcspResp;
                nloglogger.Trace("GetRelatedOCSPRespTokens candidate");
                if (ConcernsCertificateByCertIssuer(ocspresp, cert))
                {
                    if (ocspresp.IsValid(startDate, endDate))
                    {
                        nloglogger.Trace("GetRelatedOCSPRespTokens candidate confirmed");
                        ocspresps.Add(ocsprespToken);
                    }
                    else
                    {
                        ocsprespsNotValid.Add(ocsprespToken);
                    }
                }
            }

            return !returnNotValidIfEmpty || ocspresps.Any() ? ocspresps : ocsprespsNotValid;
        }

        public virtual IList<CertificateAndContext> GetIssuerCertificateAndContext(OCSPRespToken ocspResp)
        {
            if (ocspResp is null)
            {
                throw new ArgumentNullException(nameof(ocspResp));
            }

            IList<CertificateAndContext> certs = new List<CertificateAndContext>();
            foreach (var token in NeededCertificateTokens)
            {
                var cert = token.CertificateAndContext;
                if (ocspResp.IsSignedBy(cert.Certificate))
                {
                    certs.Add(cert);
                }
            }
            return certs;
        }

        public override string ToString()
        {
            int count = 0;
            var builder = new StringBuilder();
            foreach (var e in Data)
            {
                if (e.Processed)
                {
                    count++;
                }
                builder.Append(e);
                builder.Append(" ");
            }
            return $"RevocationInfo contains {Count} ISignedToken and {count} of them have been verified. List : {builder.ToString()}";
        }
    }
}
