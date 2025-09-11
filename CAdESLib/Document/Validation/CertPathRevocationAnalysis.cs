using System.Collections.Generic;
using System;
using System.Linq;
using NLog;

namespace CAdESLib.Document.Validation
{
    using ResultStatus = SignatureValidationResult.ResultStatus;
    /// <summary>
    /// Validation information for a Certificate Path (from a end user certificate to the Trusted List)
    /// </summary>
    public class CertPathRevocationAnalysis
    {
        private static readonly Logger nloglogger = LogManager.GetCurrentClassLogger();

        private SignatureValidationResult summary;

        private List<CertificateVerification> certificatePathVerification = new List<CertificateVerification>();

        public CertPathRevocationAnalysis(
                IValidationContext ctx,
                IList<CertificateAndContext> neededCertificates,
                DateTime startDate,
                DateTime endDate)
        {
            summary = new SignatureValidationResult();
            if (ctx != null && neededCertificates != null)
            {
                certificatePathVerification.AddRange(
                        neededCertificates.SelectMany(
                            x => x.CertificateVerifications.Where(
                                y => y.CertificateStatus.CertificateStatus.IsValidForTime(startDate, endDate))));
            }
            summary.SetStatus(ResultStatus.VALID, null);
            if (certificatePathVerification != null)
            {
                foreach (CertificateVerification verif in certificatePathVerification)
                {
                    if (verif.Summary.IsInvalid)
                    {
                        nloglogger.Trace("invalid");
                        summary.SetStatus(ResultStatus.INVALID, verif.Summary.Description ?? "$UI_Signatures_ValidationText_CertificateIsNotValid");
                        break;
                    }
                    if (verif.Summary.IsUndetermined)
                    {
                        nloglogger.Trace("undetermined");
                        summary.SetStatus(ResultStatus.UNDETERMINED, verif.Summary.Description ?? "$UI_Signatures_ValidationText_NoRevocationData");
                    }
                }
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
            this.certificatePathVerification = certificatePathVerification.ToList();
        }
    }
}
