using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.X509;

namespace CAdESLib.Document.Validation
{
    using static CAdESLib.Document.Validation.SignatureValidationResult;
    using Result = SignatureValidationResult;
    public class CertificateVerification
    {
        public CertificateAndContext CertificateAndContext { get; set; }

        private Result? validityPeriodVerification;

        private SignatureVerification? signatureVerification;

        private RevocationVerificationResult? certificateStatus;

        public CertificateVerification(CertificateAndContext cert, IValidationContext ctx)
        {
            if (ctx is null)
            {
                throw new System.ArgumentNullException(nameof(ctx));
            }

            CertificateAndContext = cert;
            if (cert != null)
            {
                try
                {
                    cert.Certificate.CheckValidity(ctx.ValidationDate);
                    validityPeriodVerification = new Result(ResultStatus.VALID, null);
                }
                catch (CertificateExpiredException)
                {
                    validityPeriodVerification = new Result(ResultStatus.INVALID, "$UI_Signatures_ValidationText_CertificateExpired");
                }
                catch (CertificateNotYetValidException)
                {
                    validityPeriodVerification = new Result(ResultStatus.INVALID, "$UI_Signatures_ValidationText_CertificateNotYetValid");
                }
                var status = ctx.GetCertificateStatusFromContext(cert);
                if (status != null)
                {
                    certificateStatus = new RevocationVerificationResult(status);
                }

                Summary.SetStatus(ResultStatus.VALID, null);
                if (validityPeriodVerification.IsInvalid)
                {
                    Summary.SetStatus(ResultStatus.INVALID, "$UI_Signatures_ValidationText_CertificateIsNotValid");
                }
                else if (CertificateStatus != null)
                {
                    if (CertificateStatus.Status == CertificateValidity.REVOKED)
                    {
                        Summary.SetStatus(ResultStatus.INVALID, "$UI_Signatures_ValidationText_CertificateRevoked");
                    }
                    else
                    {
                        if (CertificateStatus.Status == CertificateValidity.UNKNOWN)
                        {
                            Summary.SetStatus(ResultStatus.UNDETERMINED, "$UI_Signatures_ValidationText_RevocationUnknown");
                        }
                    }
                }
                else if (!validityPeriodVerification.IsInvalid)
                {
                    Summary.SetStatus(ResultStatus.UNDETERMINED, "$UI_Signatures_ValidationText_NoRevocationData");
                }
            }
        }


        public SignatureValidationResult Summary { get; } = new SignatureValidationResult();

        /// <returns>
        /// the certificate
        /// </returns>
        public virtual X509Certificate Certificate => CertificateAndContext.Certificate;


        /// <returns>
        /// the validityPeriodVerification
        /// </returns>
        public virtual Result? ValidityPeriodVerification => validityPeriodVerification;

        /// <returns>
        /// the signatureVerification
        /// </returns>
        public virtual SignatureVerification? SignatureVerification => signatureVerification;

        /// <returns>
        /// the certificateStatus
        /// </returns>
        public virtual RevocationVerificationResult CertificateStatus
        {
            get
            {
                if (certificateStatus == null)
                {
                    return new RevocationVerificationResult();
                }
                return certificateStatus;
            }
        }

        /// <param>
        /// the validityPeriodVerification to set
        /// </param>
        public virtual void SetValidityPeriodVerification(Result validityPeriodVerification)
        {
            this.validityPeriodVerification = validityPeriodVerification;
        }

        /// <param>
        /// the signatureVerification to set
        /// </param>
        public virtual void SetSignatureVerification(SignatureVerification signatureVerification)
        {
            this.signatureVerification = signatureVerification;
        }

        /// <param>
        /// the certificateStatus to set
        /// </param>
        public virtual void SetCertificateStatus(RevocationVerificationResult certificateStatus)
        {
            this.certificateStatus = certificateStatus;
        }
    }
}
