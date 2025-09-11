using CAdESLib.Helpers;
using NLog;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using System;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Fetch revocation data from a certificate by querying a OCSP server first and then an CRL server if no OCSP response
    /// could be retrieved.
    /// </summary>
    public class OCSPAndCRLCertificateVerifier : ICertificateStatusVerifier
    {
        private const string OCSPDoneMessage = "OCSP validation done, don't need for CRL";
        private const string CLRDoneMessage = "CRL check has been performed. Valid or not, the verification is done";
        private const string NoResponceMessage = "We had no response from OCSP nor CRL";
        private static readonly Logger nloglogger = LogManager.GetCurrentClassLogger();
        private readonly CmsSignedData cms;
        private readonly ICertificateStatusVerifier ocspVerifier;
        private readonly ICertificateStatusVerifier crlVerifier;
        private readonly IRuntimeValidatingParams? runtimeParams;
        private readonly ICryptographicProvider cryptographicProvider;

        public OCSPAndCRLCertificateVerifier(
                CmsSignedData cms,
                ICertificateStatusVerifier ocspVerifier,
                ICertificateStatusVerifier crlVerifier,
                IRuntimeValidatingParams? runtimeParams,
                ICryptographicProvider cryptographicProvider
                )
        {
            this.cms = cms;
            this.ocspVerifier = ocspVerifier;
            this.crlVerifier = crlVerifier;
            this.runtimeParams = runtimeParams;
            this.cryptographicProvider = cryptographicProvider;
        }

        public virtual CertificateStatus? Check(X509Certificate? cert, X509Certificate? potentialIssuer, DateTime startDate, DateTime endDate)
        {
            nloglogger.Trace($"Start checking. startDate={startDate}, endDate={endDate}, cert={cert?.SubjectDN}");

            if (cert is null)
            {
                throw new ArgumentNullException(nameof(cert));
            }

            if (potentialIssuer == null)
            {
                return null;
            }

            var result = new CertificateStatus
            {
                Certificate = cert,
                StartDate = startDate,
                EndDate = endDate,
                IssuerCertificate = potentialIssuer,
                Validity = CertificateValidity.UNKNOWN
            };
            var revocationValue = cms.GetRevocationValue(this.cryptographicProvider, cert!);
            if (revocationValue is BasicOcspResp respValue)
            {
                nloglogger.Trace("there is ocsp");
                result = this.VerifyValue(
                    result,
                    respValue,
                    cert,
                    potentialIssuer,
                    startDate,
                    endDate);
            }
            else if (revocationValue is X509Crl crlValue)
            {
                nloglogger.Trace("there is crl");
                result = this.VerifyValue(
                    result,
                    crlValue,
                    cert,
                    potentialIssuer,
                    startDate,
                    endDate);
            }
            else
            {
                nloglogger.Trace("there is no stored revocation data");
                result = null;
            }
            if (result is null || result.Validity == CertificateValidity.UNKNOWN && !(runtimeParams?.OfflineValidating ?? false))
            {
                nloglogger.Trace("OCSP request for " + cert.SubjectDN);
                var ocspResult = ocspVerifier.Check(cert, potentialIssuer, startDate, endDate);

                if (
                        ocspResult != null &&
                        ocspResult.Validity is not null &&
                        ocspResult.Validity != CertificateValidity.UNKNOWN &&
                        ocspResult.StatusSourceType != ValidatorSourceType.OCSP_NO_CHECK)
                {
                    nloglogger.Trace(OCSPDoneMessage);
                    return ocspResult;
                }
                else
                {
                    nloglogger.Info($"No OCSP check performed, looking for a CRL for {cert.SubjectDN},serial={cert.SerialNumber.ToString(16)}");
                    var crlResult = crlVerifier.Check(cert, potentialIssuer, startDate, endDate);
                    if (
                            crlResult != null &&
                            crlResult.Validity is not null)
                    {
                        nloglogger.Trace(CLRDoneMessage);
                        return crlResult;
                    }
                    else
                    {
                        if (ocspResult?.StatusSourceType == ValidatorSourceType.OCSP_NO_CHECK)
                        {
                            return ocspResult;
                        }
                        nloglogger.Trace(NoResponceMessage);
                        return null;
                    }
                }
            }

            return result;
        }

        public CertificateStatus? VerifyValue(
                CertificateStatus status,
                BasicOcspResp? ocspResp,
                X509Certificate certificate,
                X509Certificate issuerCertificate,
                DateTime startDate,
                DateTime endDate)
        {
            return ocspVerifier.VerifyValue(
                status,
                ocspResp,
                certificate,
                issuerCertificate,
                startDate,
                endDate);
        }
        public CertificateStatus? VerifyValue(
                CertificateStatus status,
                X509Crl? crl,
                X509Certificate certificate,
                X509Certificate issuerCertificate,
                DateTime startDate,
                DateTime endDate)
        {
            return crlVerifier.VerifyValue(
                status,
                crl,
                certificate,
                issuerCertificate,
                startDate,
                endDate);
        }
    }
}
