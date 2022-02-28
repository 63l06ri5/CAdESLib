namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Information about the QCStatement in the certificate
    /// </summary>
    public class QCStatementInformation
    {
        private SignatureValidationResult qCPPresent;

        private SignatureValidationResult qCPPlusPresent;

        private SignatureValidationResult qcCompliancePresent;

        private SignatureValidationResult qcSCCDPresent;

        public virtual SignatureValidationResult QCPPresent => qCPPresent;

        /// <param name="qCPPresent"></param>
        public virtual void SetQCPPresent(SignatureValidationResult qCPPresent)
        {
            this.qCPPresent = qCPPresent;
        }

        public virtual SignatureValidationResult QCPPlusPresent => qCPPlusPresent;

        /// <param name="qCPPlusPresent"></param>
        public virtual void SetQCPPlusPresent(SignatureValidationResult qCPPlusPresent)
        {
            this.qCPPlusPresent = qCPPlusPresent;
        }

        public virtual SignatureValidationResult QcCompliancePresent => qcCompliancePresent;

        /// <param name="qcCompliancePresent"></param>
        public virtual void SetQcCompliancePresent(SignatureValidationResult qcCompliancePresent)
        {
            this.qcCompliancePresent = qcCompliancePresent;
        }

        public virtual SignatureValidationResult QcSCCDPresent => qcSCCDPresent;

        /// <param name="qcSCCDPresent"></param>
        public virtual void SetQcSCCDPresent(SignatureValidationResult qcSCCDPresent)
        {
            this.qcSCCDPresent = qcSCCDPresent;
        }

        public QCStatementInformation(SignatureValidationResult qCPPresent, SignatureValidationResult qCPPlusPresent, SignatureValidationResult qcCompliancePresent, SignatureValidationResult qcSCCDPresent)
        {
            this.qCPPresent = qCPPresent;
            this.qCPPlusPresent = qCPPlusPresent;
            this.qcCompliancePresent = qcCompliancePresent;
            this.qcSCCDPresent = qcSCCDPresent;
        }
    }
}
