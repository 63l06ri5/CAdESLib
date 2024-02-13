namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Information about the QCStatement in the certificate
    /// </summary>
    public class QCStatementInformation
    {
        public SignatureValidationResult? QCPPresent { get; set; }

        public SignatureValidationResult? QCPPlusPresent { get; set; }

        public SignatureValidationResult? QcCompliancePresent { get; set; }

        public SignatureValidationResult? QcSCCDPresent { get; set; }

        public QCStatementInformation(SignatureValidationResult? qCPPresent, SignatureValidationResult? qCPPlusPresent, SignatureValidationResult? qcCompliancePresent, SignatureValidationResult? qcSCCDPresent)
        {
            this.QCPPresent = qCPPresent;
            this.QCPPlusPresent = qCPPlusPresent;
            this.QcCompliancePresent = qcCompliancePresent;
            this.QcSCCDPresent = qcSCCDPresent;
        }
    }
}
