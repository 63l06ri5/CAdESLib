using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using System;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Implements a check that can be executed for a certificate.
    /// </summary>
    public interface ICertificateStatusVerifier
    {
        /// <summary>
        /// Check the validity of the certificate at the validationDate.
        /// </summary>
        /// <remarks>
        /// Check the validity of the certificate at the validationDate. The operation return a CertificateStatus if the
        /// check could be executed. The result of the validation is contained in the object. This mean by example that if
        /// there is some OCSP response saying that the certificate is invalid at the validation date, then the operation
        /// return a CertificateStatus (a response has been found) but the status is invalid.
        /// </remarks>
        /// <param name="certificate">
        /// The certificate to be verified
        /// </param>
        /// <param name="issuerCertificate">
        /// This (potential) issuer of the certificate
        /// </param>
        /// <param name="startDate">
        /// The start time for which the validation has to be done (maybe in the past)
        /// </param>
        /// <param name="endDate">
        /// The end time for which the validation has to be done (maybe in the past)
        /// </param>
        /// <returns>
        /// A CertificateStatus if the check could be performed. (But still, the certificate can be REVOKED). Null
        /// otherwise.
        /// </returns>
        CertificateStatus? Check(X509Certificate certificate, X509Certificate? issuerCertificate, DateTime startDate, DateTime endDate);

        CertificateStatus? VerifyValue(
                CertificateStatus status,
                BasicOcspResp? ocspResp,
                X509Certificate certificate,
                X509Certificate issuerCertificate,
                DateTime startDate,
                DateTime endDate);

        CertificateStatus? VerifyValue(
                CertificateStatus status,
                X509Crl? crl,
                X509Certificate certificate,
                X509Certificate issuerCertificate,
                DateTime startDate,
                DateTime endDate);
    }
}
