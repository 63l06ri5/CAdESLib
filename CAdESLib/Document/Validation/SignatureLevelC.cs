using System;
using System.Collections.Generic;
using System.Text;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Validation information of level -C (XAdES, CAdES) of a signature.
    /// </summary>
    public class SignatureLevelC : SignatureLevel
    {
        private readonly SignatureValidationResult certificateRefsVerification;

        private readonly SignatureValidationResult revocationRefsVerification;

        public SignatureLevelC(SignatureValidationResult levelReached, SignatureValidationResult certificateRefsVerification, SignatureValidationResult
             revocationRefsVerification) : base(levelReached)
        {
            this.certificateRefsVerification = certificateRefsVerification;
            this.revocationRefsVerification = revocationRefsVerification;
        }

        /// <returns>
        /// the certificateRefsVerification
        /// </returns>
        public virtual SignatureValidationResult CertificateRefsVerification => certificateRefsVerification;

        /// <returns>
        /// the revocationRefsVerification
        /// </returns>
        public virtual SignatureValidationResult RevocationRefsVerification => revocationRefsVerification;
    }
}
