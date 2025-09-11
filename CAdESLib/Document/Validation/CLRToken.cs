using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System.Collections.Generic;
using System;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// CRL Signed Token
    /// </summary>
    public class CRLToken : ISignedToken
    {
        public readonly X509Crl Crl;

        private X509Certificate? signer;

        public List<object?> RootCause { get; } = new List<object?>();

        public CRLToken(X509Crl crl, object rootCause)
        {
            Crl = crl;
            RootCause.Add(rootCause);
        }

        public virtual X509Name GetSignerSubjectName()
        {
            return Crl.IssuerDN;
        }

        public virtual bool IsSignedBy(X509Certificate potentialIssuer)
        {
            try
            {
                Crl.Verify(potentialIssuer.GetPublicKey());
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

        public virtual ICertificateSource? GetWrappedCertificateSource()
        {
            return null;
        }

        public DateTime ThisUpdate => Crl.ThisUpdate;

        public override int GetHashCode()
        {
            int prime = 31;
            int result = 1;
            result = prime * result + ((Crl == null) ? 0 : Crl.GetHashCode());
            return result;
        }

        public override bool Equals(object? obj)
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
            CRLToken other = (CRLToken) obj;
            if (Crl == null)
            {
                if (other.Crl != null)
                {
                    return false;
                }
            }
            else
            {
                if (!Crl.Equals(other.Crl))
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

        public X509Certificate? GetSigner() => signer;
    }
}
