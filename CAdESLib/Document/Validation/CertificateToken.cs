using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.X509;
using System;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// SignedToken containing a X509Certificate
    /// </summary>
    public class CertificateToken : ISignedToken
    {
        private readonly ICertificateSourceFactory sourceFactory;

        private readonly CertificateAndContext cert;

        private CertificateStatus status;

        /// <summary>
        /// Create a CertificateToken
        /// </summary>
        public CertificateToken(CertificateAndContext cert, ICertificateSourceFactory sourceFactory)
        {
            this.cert = cert;
            this.sourceFactory = sourceFactory;
        }

        public virtual X509Name GetSignerSubjectName()
        {
            return cert.Certificate.IssuerDN;
        }

        /// <returns>
        /// the cert
        /// </returns>
        public virtual CertificateAndContext GetCertificateAndContext()
        {
            return cert;
        }

        /// <returns>
        /// the cert
        /// </returns>
        public virtual X509Certificate GetCertificate()
        {
            return cert.Certificate;
        }

        public virtual bool IsSignedBy(X509Certificate potentialIssuer)
        {
            try
            {
                GetCertificate().Verify(potentialIssuer.GetPublicKey());
                return true;
            }
            catch (InvalidKeyException)
            {
                return false;
            }
            catch (CertificateException)
            {
                return false;
            }
            catch (SignatureException)
            {
                return false;
            }
        }

        /// <param>
        /// the status to set
        /// </param>
        public virtual void SetStatus(CertificateStatus status)
        {
            this.status = status;
        }

        /// <returns>
        /// the status
        /// </returns>
        public virtual CertificateStatus GetStatus()
        {
            return status;
        }

        /// <summary>
        /// An X509Certificate may contain information about his issuer in the AIA attribute.
        /// </summary>
        public virtual ICertificateSource GetWrappedCertificateSource()
        {
            if (sourceFactory != null)
            {
                ICertificateSource source = sourceFactory.CreateAIACertificateSource(GetCertificate());
                return source;
            }
            else
            {
                return null;
            }
        }

        public override int GetHashCode()
        {
            int prime = 31;
            int result = 1;
            try
            {
                result = prime * result + ((cert == null) ? 0 : Convert.ToBase64String(GetCertificate().GetEncoded()).GetHashCode());
            }
            catch (CertificateException)
            {
                return prime;
            }
            return result;
        }

        public override bool Equals(object obj)
        {
            if (this == obj)
            {
                return true;
            }
            if (obj == null)
            {
                return false;
            }
            if (GetType() != obj.GetType())
            {
                return false;
            }
            CertificateToken other = (CertificateToken)obj;
            if (cert == null)
            {
                if (other.cert != null)
                {
                    return false;
                }
            }
            else
            {
                if (!cert.Equals(other.cert))
                {
                    return false;
                }
            }
            return true;
        }

        public override string ToString()
        {
            return "Certificate[subjectName=\"" + GetCertificate().SubjectDN + "\",issuedBy=\""
                 + GetCertificate().IssuerDN + "\"]";
        }
    }
}
