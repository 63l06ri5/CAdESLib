using System.Collections.Generic;

namespace CAdESLib.Document.Validation
{
    using ResultStatus = SignatureValidationResult.ResultStatus;
    /// <summary>
    /// Validation information for a Certificate Path (from a end user certificate to the Trusted List)
    /// </summary>
    public class CertPathRevocationAnalysis
    {
        private SignatureValidationResult summary;

        private IList<CertificateVerification> certificatePathVerification = new List<CertificateVerification>();

        private TrustedListInformation? trustedListInformation;

        public CertPathRevocationAnalysis(IValidationContext ctx, TrustedListInformation info, IList<CertificateAndContext> neededCertificates)
        {
            summary = new SignatureValidationResult();
            trustedListInformation = info;
            if (ctx != null && neededCertificates != null)
            {
                foreach (CertificateAndContext cert in neededCertificates)
                {
                    CertificateVerification verif = new CertificateVerification(cert, ctx);
                    certificatePathVerification.Add(verif);
                }
            }
            summary.SetStatus(ResultStatus.VALID, null);
            if (certificatePathVerification != null)
            {
                foreach (CertificateVerification verif in certificatePathVerification)
                {
                    if (verif.Summary.IsInvalid)
                    {
                        summary.SetStatus(ResultStatus.INVALID, verif.Summary.Description ?? "$UI_Signatures_ValidationText_CertificateIsNotValid");
                        break;
                    }
                    if (verif.Summary.IsUndetermined)
                    {
                        summary.SetStatus(ResultStatus.UNDETERMINED, verif.Summary.Description ?? "$UI_Signatures_ValidationText_NoRevocationData");
                    }
                }
            }
            if (trustedListInformation != null)
            {
                if (!trustedListInformation.IsServiceWasFound)
                {
                    summary.SetStatus(ResultStatus.INVALID, "$UI_Signatures_ValidationText_NoTrustedListServiceWasFound");
                }
            }
            else
            {
                summary.SetStatus(ResultStatus.INVALID, "$UI_Signatures_ValidationText_NoTrustedListServiceWasFound");
            }
        }

        /// <returns>
        /// the summary
        /// </returns>
        public virtual SignatureValidationResult Summary => summary;

        /// <returns>
        /// the certificatePathVerification
        /// </returns>
        public virtual IList<CertificateVerification> CertificatePathVerification => certificatePathVerification;

        /// <returns>
        /// the trustedListInformation
        /// </returns>
        public virtual TrustedListInformation? TrustedListInformation => trustedListInformation;

        /// <param>
        /// the summary to set
        /// </param>
        public virtual void SetSummary(SignatureValidationResult summary)
        {
            this.summary = summary;
        }

        /// <param>
        /// the certificatePathVerification to set
        /// </param>
        public virtual void SetCertificatePathVerification(IList<CertificateVerification>
             certificatePathVerification)
        {
            this.certificatePathVerification = certificatePathVerification;
        }

        /// <param>
        /// the trustedListInformation to set
        /// </param>
        public virtual void SetTrustedListInformation(TrustedListInformation trustedListInformation)
        {
            this.trustedListInformation = trustedListInformation;
        }
    }
}
