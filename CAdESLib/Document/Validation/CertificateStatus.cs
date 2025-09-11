using Org.BouncyCastle.X509;
using System;

namespace CAdESLib.Document.Validation
{
    public class CertificateStatus
    {
        /// <summary>
        /// Get or Set the certificate for which the status is relevant
        /// </summary>         
        public X509Certificate? Certificate { get; set; }

        /// <summary>
        /// Get or Set the issuer certificate
        /// </summary>        
        public X509Certificate? IssuerCertificate { get; set; }

        /// <summary>
        /// Result of the validity check
        /// </summary>
        public CertificateValidity? Validity { get; set; }

        /// <summary>
        /// Data from which the status is coming
        /// </summary>        
        public StatusSource StatusSource { get; set; } = new StatusSource();

        /// <summary>
        /// Type of source from which the status is coming
        /// </summary>        
        public ValidatorSourceType StatusSourceType { get; set; }

        /// <summary>
        /// The revocationObjectIssuingTime
        /// </summary>
        public DateTime RevocationObjectIssuingTime { get; set; }

        /// <summary>
        /// The revocationDate
        /// </summary>
        public DateTime RevocationDate { get; set; }

        /// <summary>
        /// Date when the validation was performed
        /// </summary>
        public DateTime StartDate { get; set; }

        public DateTime EndDate { get; set; }

        public static CertificateStatus GetNotAvailableStatus(X509Certificate certificate, DateTime startDate, DateTime endDate)
        {
            return new CertificateStatus()
            {
                Certificate = certificate,
                StatusSource = StatusSource.GetNotAvailableStatus(startDate, endDate),
                StartDate = startDate,
                EndDate = endDate,
                Validity = CertificateValidity.UNKNOWN
            };
        }

        public bool IsValidForTime(DateTime startDate, DateTime endDate) => 
            StatusSourceType == ValidatorSourceType.TRUSTED_LIST ||
            StatusSource.IsValidForTime(startDate, endDate) ||
            StartDate.CompareTo(startDate) >= 0 && EndDate.CompareTo(endDate) <= 0;

        public override string ToString()
        {
            return "CertificateStatus[The certificate of '" + (Certificate != null ? Certificate
                .SubjectDN.ToString() : "<<!!null!!>>") + "' is " + (Validity?.ToString()) + " at period " + StartDate + "-" + EndDate + " according to " + (StatusSourceType.ToString()) + "]";
        }
    }
}
