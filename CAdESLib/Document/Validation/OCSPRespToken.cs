using NLog;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using System.Collections.Generic;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// OCSP Signed Token
    /// </summary>
    public class OCSPRespToken : ISignedToken
    {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        private readonly BasicOcspResp ocspResp;

        public OCSPRespToken(BasicOcspResp ocspResp)
        {
            this.ocspResp = ocspResp;
        }

        /// <returns>
        /// the ocspResp
        /// </returns>
        public virtual BasicOcspResp GetOcspResp()
        {
            return ocspResp;
        }

        public virtual X509Name GetSignerSubjectName()
        {
            if (ocspResp.ResponderId.ToAsn1Object().Name != null)
            {
                return ocspResp.ResponderId.ToAsn1Object().Name;
            }
            else
            {
                IList<X509Certificate> certs = ((OCSPRespCertificateSource)GetWrappedCertificateSource()).GetCertificates();
                foreach (X509Certificate c in certs)
                {
                    if (IsSignedBy(c))
                    {
                        return c.SubjectDN;
                    }
                }
                logger.Warn("Don't found an signer for OCSPToken in the " + certs.Count + " certificates "
                     + certs);
                return null;
            }
        }

        public virtual bool IsSignedBy(X509Certificate potentialIssuer)
        {
            try
            {
                return ocspResp.Verify(potentialIssuer.GetPublicKey());
            }
            catch (OcspException)
            {
                return false;
            }
        }

        public virtual ICertificateSource GetWrappedCertificateSource()
        {
            return new OCSPRespCertificateSource(ocspResp);
        }

        public override int GetHashCode()
        {
            int prime = 31;
            int result = 1;
            result = prime * result + ((ocspResp == null) ? 0 : ocspResp.GetHashCode());
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
            OCSPRespToken other = (OCSPRespToken)obj;
            if (ocspResp == null)
            {
                if (other.ocspResp != null)
                {
                    return false;
                }
            }
            else
            {
                if (!ocspResp.Equals(other.ocspResp))
                {
                    return false;
                }
            }
            return true;
        }

        public override string ToString()
        {
            return "OcspResp[signedBy=" + GetSignerSubjectName() + "]";
        }
    }
}
