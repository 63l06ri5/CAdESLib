namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Validation information for level XL (CAdES, XAdES).
    /// </summary>
    public class SignatureLevelXL : SignatureLevel
    {
        private readonly SignatureValidationResult certificateValuesVerification;

        private readonly SignatureValidationResult revocationValuesVerification;

        public SignatureLevelXL(SignatureValidationResult levelReached, SignatureValidationResult certificateValuesVerification, SignatureValidationResult revocationValuesVerification) : base(levelReached)
        {
            this.certificateValuesVerification = certificateValuesVerification;
            this.revocationValuesVerification = revocationValuesVerification;
        }

        /// <returns>
        /// the certificateRefsVerification
        /// </returns>
        public virtual SignatureValidationResult CertificateValuesVerification => certificateValuesVerification;

        /// <returns>
        /// the revocationRefsVerification
        /// </returns>
        public virtual SignatureValidationResult RevocationValuesVerification => revocationValuesVerification;
    }
}
