using System;
using System.Collections.Generic;
using System.Text;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Contains information about the validity of a signature.
    /// </summary>
    public class SignatureVerification
    {
        /// <summary>
        /// specifies if the signature is mathematically correct or not
        /// </summary>
        /// <returns>
        /// the signature verification result
        /// </returns>
        public SignatureValidationResult SignatureVerificationResult { get; private set; }

        /// <summary>
        /// Provides the name of the algorithm applied for the signature
        /// </summary>
        /// <returns>
        /// the signature algorithm
        /// </returns>
        public string SignatureAlgorithm { get; private set; }

        public SignatureVerification(SignatureValidationResult signatureVerificationResult, string signatureAlgorithm)
        {
            SignatureVerificationResult = signatureVerificationResult;
            SignatureAlgorithm = signatureAlgorithm;
        }
    }
}
