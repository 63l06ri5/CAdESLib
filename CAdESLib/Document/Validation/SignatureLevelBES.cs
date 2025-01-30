using CAdESLib.Document.Signature;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Validation information for level BES
    /// </summary>
    public class SignatureLevelBES : SignatureLevel
    {
        private readonly X509Certificate? signingCertificate;

        private readonly SignatureValidationResult signingCertRefVerification;

        private readonly SignatureVerification[]? counterSignaturesVerification;

        private readonly IList<TimestampVerificationResult>? timestampsVerification;

        private readonly IList<X509Certificate>? certificates;

        private readonly DateTime signingTime;

        private readonly string? location;

        private readonly string[]? claimedSignerRole;

        private readonly string? contentType;

        public SignatureLevelBES(
            SignatureValidationResult levelReached,
            IAdvancedSignature? signature,
            SignatureValidationResult signingCertificateVerification,
            SignatureVerification[]? counterSignatureVerification,
            IList<TimestampVerificationResult>? timestampsVerification) : base(levelReached)
        {
            signingCertRefVerification = signingCertificateVerification;
            counterSignaturesVerification = counterSignatureVerification;
            this.timestampsVerification = timestampsVerification;
            if (signature != null)
            {
                certificates = signature.Certificates;
                signingCertificate = signature.SigningCertificate;
                signingTime = (signature.SigningTime?.Value ?? DateTime.Now).ToUniversalTime();
                location = signature.Location;
                claimedSignerRole = signature.ClaimedSignerRoles;
                contentType = signature.ContentType;
            }
        }

        /// <returns>
        /// the signingCertificateVerification
        /// </returns>
        public virtual SignatureValidationResult SigningCertRefVerification => signingCertRefVerification;

        /// <returns>
        /// the counterSignaturesVerification
        /// </returns>
        public virtual SignatureVerification[]? CounterSignaturesVerification => counterSignaturesVerification;

        /// <returns>
        /// the timestampsVerification
        /// </returns>
        public virtual IList<TimestampVerificationResult>? TimestampsVerification => timestampsVerification;

        public virtual IList<X509Certificate>? Certificates => certificates;

        public virtual string? Location => location;

        public virtual string? ContentType => contentType;

        public virtual string[]? ClaimedSignerRoles => claimedSignerRole;

        public virtual X509Certificate? SigningCertificate => signingCertificate;

        public virtual DateTime SigningTime => signingTime;
    }
}
