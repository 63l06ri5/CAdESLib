using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Text;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// RevocationData for a specific ISignedToken
    /// </summary>
    public class RevocationData
    {
        private readonly ISignedToken targetToken;

        private object revocationData;

        public RevocationData()
        {
        }

        public RevocationData(ISignedToken signedToken)
        {
            targetToken = signedToken;
        }

        /// <summary>
        /// The target of this revocation data
        /// </summary>
        public virtual ISignedToken GetTargetToken()
        {
            return targetToken;
        }

        /// <summary>
        /// The value of the revocation data
        /// </summary>
        public virtual object GetRevocationData()
        {
            return revocationData;
        }

        /// <summary>
        /// Set the value of the revocation data
        /// </summary>
        public virtual void SetRevocationData(object revocationData)
        {
            if (targetToken is CertificateToken)
            {
                if (!(revocationData is CertificateSourceType) && !(revocationData is BasicOcspResp) && !(revocationData is X509Crl))
                {
                    throw new ArgumentException("For " + targetToken + " only OCSP, CRL or CertificateSourceType are valid. (Trying to add "
                         + revocationData.GetType().Name + ").");
                }
            }
            this.revocationData = revocationData;
        }

        public override string ToString()
        {
            string data = null;
            if (GetRevocationData() is X509Crl)
            {
                data = "CRL[from=" + ((X509Crl)GetRevocationData()).IssuerDN + "]";
            }
            else
            {
                if (GetRevocationData() is BasicOcspResp)
                {
                    data = "OCSP[from" + ((BasicOcspResp)GetRevocationData()).ResponderId.ToAsn1Object().Name + "]";
                }
                else
                {
                    if (GetRevocationData() is X509Certificate)
                    {
                        data = "Certificate[subjectName=" + ((X509Certificate)GetRevocationData()).SubjectDN + "]";
                    }
                    else
                    {
                        if (GetRevocationData() != null)
                        {
                            data = GetRevocationData().ToString();
                        }
                        else
                        {
                            data = "*** NO VALIDATION DATA AVAILABLE ***";
                        }
                    }
                }
            }
            return "RevocationData[token=" + targetToken + ",data=" + data + "]";
        }
    }
}
