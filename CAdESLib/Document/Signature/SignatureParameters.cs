using CAdESLib.Helpers;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;

namespace CAdESLib.Document.Signature
{
    public class SignatureParameters
    {
        /// <summary>
        /// Get or Set the signing date
        /// </summary>        
        public virtual DateTime SigningDate { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Get or Set the signing certificate
        /// </summary>        
        public virtual X509Certificate? SigningCertificate { get; set; }

        /// <summary>
        /// Get or Set the certificate chain
        /// </summary>		
        public virtual IList<X509Certificate>? CertificateChain { get; set; }

        /// <summary>
        /// Return or Set the type of signature policy
        /// </summary>
        public virtual SignaturePolicy SignaturePolicy { get; set; }

        /// <summary>
        /// Get or Set the signature policy (EPES)
        /// </summary>
        public virtual string? SignaturePolicyID { get; set; }

        /// <summary>
        /// Return or Set the hash algorithm for the signature policy 
        /// or Set the hash algorithm for the explicit signature policy
        /// </summary>
        public virtual string? SignaturePolicyHashAlgo { get; set; }

        /// <summary>
        /// Get the hash value of the explicit signature policy 
        /// or Set the hash value of implicit signature policy
        /// </summary>        
        public virtual byte[]? SignaturePolicyHashValue { get; set; }

        /// <summary>
        /// Get or Set claimed role
        /// </summary>
        public virtual string? ClaimedSignerRole { get; set; }

        /// <summary>
        /// Get or Set signature format
        /// </summary>
        public virtual SignatureProfile SignatureProfile { get; set; }

        /// <summary>
        /// Get or Set Signature packaging
        /// </summary>
        public virtual SignaturePackaging SignaturePackaging { get; set; }

        public virtual string DigestAlgorithmOID { get; set; }
        public virtual string EncriptionAlgorithmOID { get; set; }

        /// <summary>
        /// Should create a new attribute if it already exists when extending signature
        /// </summary>
        /// <remarks>
        public virtual bool CreateNewAttributeIfExist { get; private set; }

        public string SignatureName
        {
            get
            {
                return CmsSignedHelper.Instance.GetDigestAlgName(DigestAlgorithmOID) + "with" + CmsSignedHelper.Instance.GetEncryptionAlgName(EncriptionAlgorithmOID);
            }
        }

        public string DigestWithEncriptionOID
        {
            get
            {
                return new DefaultSignatureAlgorithmIdentifierFinder().Find(this.SignatureName).Algorithm.Id;
            }
        }

        public SignatureParameters()
        {
            SignaturePolicy = SignaturePolicy.NO_POLICY;
            DigestAlgorithmOID = DigestAlgorithm.SHA1.OID;
            EncriptionAlgorithmOID = Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.RsaEncryption.Id;
            CreateNewAttributeIfExist = false;
        }

        public SignatureParameters(SignatureParameters parameters)
        {
            SigningDate = parameters.SigningDate;
            SigningCertificate = parameters.SigningCertificate;
            CertificateChain = parameters.CertificateChain;
            SignaturePolicy = parameters.SignaturePolicy;
            SignaturePolicyID = parameters.SignaturePolicyID;
            SignaturePolicyHashAlgo = parameters.SignaturePolicyHashAlgo;
            SignaturePolicyHashValue = parameters.SignaturePolicyHashValue;
            ClaimedSignerRole = parameters.ClaimedSignerRole;
            SignatureProfile = parameters.SignatureProfile;
            SignaturePackaging = parameters.SignaturePackaging;
            DigestAlgorithmOID = parameters.DigestAlgorithmOID;
            EncriptionAlgorithmOID = parameters.EncriptionAlgorithmOID;
            CreateNewAttributeIfExist = parameters.CreateNewAttributeIfExist;
        }
    }

}
