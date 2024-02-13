using System.Collections.Generic;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Validation information for level X (CAdES, XAdES).
    /// </summary>
    public class SignatureLevelX : SignatureLevel
    {
        private readonly TimestampVerificationResult[]? signatureAndRefsTimestampsVerification;

        private readonly TimestampVerificationResult[]? referencesTimestampsVerification;

        public SignatureLevelX(SignatureValidationResult levelReached) : base(levelReached)
        {
        }

        public SignatureLevelX(
            SignatureValidationResult levelReached,
            TimestampVerificationResult[]? signatureAndRefsTimestampsVerification,
            TimestampVerificationResult[]? referencesTimestampsVerification) : base(levelReached)
        {
            this.signatureAndRefsTimestampsVerification = signatureAndRefsTimestampsVerification;
            this.referencesTimestampsVerification = referencesTimestampsVerification;
        }

        public SignatureLevelX(SignatureValidationResult levelReached, List<TimestampVerificationResult> signatureAndRefsTimestampsVerification, List<TimestampVerificationResult> referencesTimestampsVerification) : base(levelReached)
        {
            if (signatureAndRefsTimestampsVerification is null)
            {
                throw new System.ArgumentNullException(nameof(signatureAndRefsTimestampsVerification));
            }

            if (referencesTimestampsVerification is null)
            {
                throw new System.ArgumentNullException(nameof(referencesTimestampsVerification));
            }

            this.signatureAndRefsTimestampsVerification = signatureAndRefsTimestampsVerification.ToArray();
            this.referencesTimestampsVerification = referencesTimestampsVerification.ToArray();
        }

        /// <returns>
        /// the signatureAndRefsTimestampsVerification
        /// </returns>
        public virtual TimestampVerificationResult[]? SignatureAndRefsTimestampsVerification => signatureAndRefsTimestampsVerification;

        /// <returns>
        /// the referencesTimestampsVerification
        /// </returns>
        public virtual TimestampVerificationResult[]? ReferencesTimestampsVerification => referencesTimestampsVerification;
    }
}
