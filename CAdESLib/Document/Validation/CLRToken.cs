using System;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// CRL Signed Token
    /// </summary>
    public class CRLToken : ISignedToken
    {
        private readonly X509Crl x509crl;

        private X509Certificate signer;

        public CRLToken(X509Crl crl)
        {
            x509crl = crl;
        }
        /// <returns>
        /// the x509crl
        /// </returns>
        public virtual X509Crl GetX509crl()
        {
            return x509crl;
        }

        public virtual X509Name GetSignerSubjectName()
        {
            return x509crl.IssuerDN;
        }

        public virtual bool IsSignedBy(X509Certificate potentialIssuer)
        {
            try
            {
                x509crl.Verify(potentialIssuer.GetPublicKey());
                signer = potentialIssuer;
                return true;
            }
            catch (InvalidKeyException)
            {
                return false;
            }
            catch (SignatureException)
            {
                return false;
            }
        }

        public virtual ICertificateSource GetWrappedCertificateSource()
        {
            return null;
        }

        public override int GetHashCode()
        {
            int prime = 31;
            int result = 1;
            result = prime * result + ((x509crl == null) ? 0 : x509crl.GetHashCode());
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
            CRLToken other = (CRLToken)obj;
            if (x509crl == null)
            {
                if (other.x509crl != null)
                {
                    return false;
                }
            }
            else
            {
                if (!x509crl.Equals(other.x509crl))
                {
                    return false;
                }
            }
            return true;
        }

        public override string ToString()
        {
            return "CRL[signedBy=" + GetSignerSubjectName() + "]";
        }

        public X509Certificate GetSigner() => signer;
    }
}
