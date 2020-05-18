using System;
using System.Collections.Generic;
using System.Text;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Validation information for level T (CAdES, PAdES, XAdES) of a signature.
    /// </summary>
    public class SignatureLevelT : SignatureLevel
    {
        private readonly IList<TimestampVerificationResult> signatureTimestampsVerification;

        public SignatureLevelT(SignatureValidationResult levelReached, IList<TimestampVerificationResult> signatureTimestampsVerification) : base(levelReached)
        {
            this.signatureTimestampsVerification = signatureTimestampsVerification;
        }

        /// <returns>
        /// the signatureTimestampVerification
        /// </returns>
        public virtual IList<TimestampVerificationResult> SignatureTimestampVerification => signatureTimestampsVerification;
    }
}
