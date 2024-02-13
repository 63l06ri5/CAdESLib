using Org.BouncyCastle.Utilities.Date;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Representation of a certificate status, used to indicate the success or the failure of the verification of revocation
    /// data
    /// </summary>
    public class RevocationVerificationResult
    {
        private readonly CertificateStatus certificateStatus;

        public RevocationVerificationResult(CertificateStatus? certificateStatus)
        {
            if (certificateStatus != null)
            {
                this.certificateStatus = certificateStatus;
            }
            else
            {
                this.certificateStatus = new CertificateStatus
                {
                    Validity = CertificateValidity.UNKNOWN
                };
            }
        }

        public RevocationVerificationResult() : this(null)
        {
        }

        public virtual CertificateValidity Status
        {
            get
            {
                if (certificateStatus == null)
                {
                    return CertificateValidity.UNKNOWN;
                }
                return certificateStatus.Validity;
            }
        }

        public virtual DateTimeObject? RevocationDate
        {
            get
            {
                if (certificateStatus == null)
                {
                    return null;
                }
                if (Status == CertificateValidity.REVOKED)
                {
                    return new DateTimeObject(certificateStatus.RevocationDate);
                }
                else
                {
                    return null;
                }
            }
        }

        public virtual CertificateStatus CertificateStatus => certificateStatus;

        public virtual DateTimeObject? IssuingTime
        {
            get
            {
                if (certificateStatus == null)
                {
                    return null;
                }
                if (Status == CertificateValidity.REVOKED)
                {
                    return new DateTimeObject(
                        certificateStatus.RevocationObjectIssuingTime);
                }
                else
                {
                    return null;
                }
            }
        }
    }
}
