using System;
using System.Collections.Generic;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.X509;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Validation information of a timestamp.
    /// </summary>
    public class TimestampVerificationResult
    {
        private SignatureValidationResult sameDigest;

        private SignatureValidationResult certPathVerification = new SignatureValidationResult();

        private string signatureAlgorithm;

        private string serialNumber;

        private DateTime creationTime;

        private string issuerName;

        private X509Certificate issuer;

        public TimestampVerificationResult()
        {
        }

        public TimestampVerificationResult(TimestampToken token)
        {
            if (token != null && token.GetTimeStamp() != null)
            {
                var signers = token.GetTimeStamp().ToCmsSignedData().GetSignerInfos().GetSigners().GetEnumerator();
                signers.MoveNext();
                signatureAlgorithm = ((SignerInformation)signers.Current).EncryptionAlgOid;
                serialNumber = token.GetTimeStamp().TimeStampInfo.SerialNumber.ToString();
                creationTime = token.GetTimeStamp().TimeStampInfo.GenTime;
                issuerName = token.GetSignerSubjectName().ToString();
                issuer = token.GetSigner();
            }
        }

        public IList<CertificateAndContext> UsedCerts { get; set; } = new List<CertificateAndContext>();

        /// <param>
        /// the sameDigest to set
        /// </param>
        public virtual void SetSameDigest(SignatureValidationResult sameDigest)
        {
            this.sameDigest = sameDigest;
        }

        /// <returns>
        /// the sameDigest
        /// </returns>
        public virtual SignatureValidationResult SameDigest => sameDigest;

        public virtual string SignatureAlgorithm => signatureAlgorithm;

        public virtual string SerialNumber => serialNumber;

        public virtual DateTime CreationTime => creationTime;

        public virtual string IssuerName => issuerName;

        public virtual X509Certificate Issuer => issuer;

        public virtual SignatureValidationResult CertPathUpToTrustedList => certPathVerification;

        /// <returns>
        /// the certPathVerification
        /// </returns>
        public virtual SignatureValidationResult CertPathVerification => certPathVerification;

        /// <param>
        /// the certPathVerification to set
        /// </param>
        public virtual void SetCertPathVerification(SignatureValidationResult certPathVerification)
        {
            this.certPathVerification = certPathVerification;
        }

        /// <param>
        /// the signatureAlgorithm to set
        /// </param>
        public virtual void SetSignatureAlgorithm(string signatureAlgorithm)
        {
            this.signatureAlgorithm = signatureAlgorithm;
        }

        /// <param>
        /// the serialNumber to set
        /// </param>
        public virtual void SetSerialNumber(string serialNumber)
        {
            this.serialNumber = serialNumber;
        }

        /// <param>
        /// the creationTime to set
        /// </param>
        public virtual void SetCreationTime(DateTime creationTime)
        {
            this.creationTime = creationTime;
        }

        /// <param>
        /// the issuerName to set
        /// </param>
        public virtual void SetIssuerName(string issuerName)
        {
            this.issuerName = issuerName;
        }
    }
}
