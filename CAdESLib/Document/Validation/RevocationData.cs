﻿using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using System;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// RevocationData for a specific ISignedToken
    /// </summary>
    public class RevocationData
    {
        private readonly ISignedToken? targetToken;

        private object? revocationData;

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
        public virtual ISignedToken? GetTargetToken()
        {
            return targetToken;
        }

        /// <summary>
        /// The value of the revocation data
        /// </summary>
        public virtual object? GetRevocationData()
        {
            return revocationData;
        }

        /// <summary>
        /// Set the value of the revocation data
        /// </summary>
        public virtual void SetRevocationData(object? revocationData)
        {
            if (targetToken is CertificateToken && !(revocationData is null))
            {
                if (!(revocationData is CertificateSourceType) && !(revocationData is BasicOcspResp) && !(revocationData is X509Crl))
                {
                    throw new ArgumentException("For " + targetToken + " only OCSP, CRL or CertificateSourceType are valid. (Trying to add " + revocationData.GetType().Name + ").");
                }
            }
            this.revocationData = revocationData;
        }

        public override string ToString()
        {
            string data;
            var revocationData = GetRevocationData();
            if (revocationData is X509Crl crl)
            {
                data = "CRL[from=" + crl.IssuerDN + "]";
            }
            else
            {
                if (revocationData is BasicOcspResp resp)
                {
                    data = "OCSP[from" + resp.ResponderId.ToAsn1Object().Name + "]";
                }
                else
                {
                    if (revocationData is X509Certificate certificate)
                    {
                        data = "Certificate[subjectName=" + certificate.SubjectDN + "]";
                    }
                    else
                    {
                        if (!(revocationData is null))
                        {
                            data = revocationData.ToString()!;
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
