using Org.BouncyCastle.X509;
using System.Collections.Generic;
using System.Runtime.Serialization;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// A certificate comes from a certain context (Trusted List, CertStore, Signature) and has somes properties
    /// </summary>
    public class CertificateAndContext
    {
        /// <summary>
        /// Create a CertificateAndContext wrapping the provided X509Certificate The default constructor for
        /// CertificateAndContext.
        /// </summary>
        public CertificateAndContext(X509Certificate cert)
            : this(cert, null)
        {
        }

        public CertificateAndContext(X509Certificate cert, ISerializable context)
        {
            Certificate = cert;
            Context = context;
        }

        public List<object> RootCause { get; set; } = new List<object>();
        public virtual X509Certificate Certificate { get; set; }
        public virtual CertificateAndContext IssuerCertificate { get; set; }
        public virtual ISerializable Context { get; set; }
        public virtual CertificateSourceType CertificateSource { get; set; }
        public CertificateStatus CertificateStatus { get; internal set; }

        public override string ToString()
        {
            return $"Certificate[for={Certificate.SubjectDN.ToString()},source={CertificateSource},issuedBy={Certificate.IssuerDN},serial={Certificate.SerialNumber.ToString(16)}]";
        }

        public override int GetHashCode()
        {
            int prime = 31;
            int result = 1;
            result = prime * result + ((Certificate == null) ? 0 : Certificate.GetHashCode());
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
            CertificateAndContext other = (CertificateAndContext)obj;
            if (Certificate == null)
            {
                if (other.Certificate != null)
                {
                    return false;
                }
            }
            else
            {
                if (!Certificate.Equals(other.Certificate))
                {
                    return false;
                }
            }
            return true;
        }
    }
}
