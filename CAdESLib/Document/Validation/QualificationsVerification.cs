namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Qualification of the certificate according to the QualificationElement of the Trusted List.
    /// </summary>
    public class QualificationsVerification
    {
        private readonly SignatureValidationResult qCWithSSCD;

        private readonly SignatureValidationResult qCNoSSCD;

        private readonly SignatureValidationResult qCSSCDStatusAsInCert;

        private readonly SignatureValidationResult qCForLegalPerson;

        /// <returns>
        /// the qCWithSSCD
        /// </returns>
        public virtual SignatureValidationResult QCWithSSCD => qCWithSSCD;

        /// <returns>
        /// the qCNoSSCD
        /// </returns>
        public virtual SignatureValidationResult QCNoSSCD => qCNoSSCD;

        /// <returns>
        /// the qCSSCDStatusAsInCert
        /// </returns>
        public virtual SignatureValidationResult QCSSCDStatusAsInCert => qCSSCDStatusAsInCert;

        /// <returns>
        /// the qCForLegalPerson
        /// </returns>
        public virtual SignatureValidationResult QCForLegalPerson => qCForLegalPerson;

        public QualificationsVerification(SignatureValidationResult qCWithSSCD, SignatureValidationResult qCNoSSCD, SignatureValidationResult qCSSCDStatusAsInCert, SignatureValidationResult qCForLegalPerson)
        {
            this.qCWithSSCD = qCWithSSCD;
            this.qCNoSSCD = qCNoSSCD;
            this.qCSSCDStatusAsInCert = qCSSCDStatusAsInCert;
            this.qCForLegalPerson = qCForLegalPerson;
        }
    }
}
