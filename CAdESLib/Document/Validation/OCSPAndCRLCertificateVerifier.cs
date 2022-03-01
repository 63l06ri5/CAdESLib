using NLog;
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
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();
        private readonly ICertificateStatusVerifier ocspVerifier;
        private readonly ICertificateStatusVerifier crlVerifier;

        public OCSPAndCRLCertificateVerifier(ICertificateStatusVerifier ocspVerifier, ICertificateStatusVerifier crlVerifier)
        {
            this.ocspVerifier = ocspVerifier;
            this.crlVerifier = crlVerifier;
        }

        public virtual CertificateStatus Check(X509Certificate cert, X509Certificate potentialIssuer, DateTime validationDate)
        {
            if (cert is null)
            {
                throw new ArgumentNullException(nameof(cert));
            }

            if (potentialIssuer == null)
            {
                return null;
            }

            logger.Info("OCSP request for " + cert.SubjectDN);
            CertificateStatus result = ocspVerifier.Check(cert, potentialIssuer, validationDate);
            if (result != null && result.Validity != CertificateValidity.UNKNOWN)
            {
                logger.Info(OCSPDoneMessage);
                return result;
            }
            else
            {
                logger.Info("No OCSP check performed, looking for a CRL for " + cert.SubjectDN);
                result = crlVerifier.Check(cert, potentialIssuer, validationDate);
                if (result != null && result.Validity != CertificateValidity.UNKNOWN)
                {
                    logger.Info(CLRDoneMessage);
                    return result;
                }
                else
                {
                    logger.Info(NoResponceMessage);
                    return null;
                }
            }
        }
    }
}
