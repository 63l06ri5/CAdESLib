using NLog;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using System.Collections.Generic;
using System;
using System.Linq;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// OCSP Signed Token
    /// </summary>
    public class OCSPRespToken : ISignedToken
    {
        private static readonly Logger nloglogger = LogManager.GetCurrentClassLogger();

        public readonly BasicOcspResp OcspResp;

        private X509Name? signerSubjectName;

        private BigInteger? signerSerialNumber;

        private X509Certificate? signerCertificate;

        private bool isSignerNotFound = false;

        public List<object?> RootCause { get; } = new List<object?>();

        public OCSPRespToken(BasicOcspResp ocspResp, object rootValidationCause)
        {
            this.OcspResp = ocspResp;
            RootCause.Add(rootValidationCause);
        }

        public virtual X509Name? GetSignerSubjectName()
        {
            if (signerSubjectName != null)
            {
                return signerSubjectName;
            }

            signerSubjectName = OcspResp.ResponderId.ToAsn1Object().Name;

            if (signerSubjectName != null)
            {
                return signerSubjectName;
            }

            if (isSignerNotFound)
            {
                return null;
            }

            if (signerCertificate != null)
            {
                return signerSubjectName = signerCertificate.SubjectDN;
            }

            signerCertificate = GetSigningCert();

            if (signerCertificate != null)
            {
                return signerSubjectName = signerCertificate.SubjectDN;
            }

            isSignerNotFound = true;

            return null;
        }

        public virtual BigInteger? GetSignerSerialNumber()
        {
            if (signerSerialNumber != null)
            {
                return signerSerialNumber;
            }

            if (isSignerNotFound)
            {
                return null;
            }

            if (signerCertificate != null)
            {
                return signerSerialNumber = signerCertificate.SerialNumber;
            }

            signerCertificate = GetSigningCert();

            if (signerCertificate != null)
            {
                return signerSerialNumber = signerCertificate.SerialNumber;
            }

            isSignerNotFound = true;

            return null;
        }

        public virtual bool IsSignedBy(X509Certificate potentialIssuer)
        {
            try
            {
                var result = OcspResp.Verify(potentialIssuer.GetPublicKey());
                if (result)
                {
                    signerCertificate = potentialIssuer;
                }
                return result;
            }
            catch (OcspException)
            {
                return false;
            }
        }

        public virtual ICertificateSource GetWrappedCertificateSource()
        {
            return new OCSPRespCertificateSource(OcspResp);
        }

        public DateTime ThisUpdate => OcspResp.Responses.First().ThisUpdate;

        public override int GetHashCode()
        {
            int prime = 31;
            int result = 1;
            int hashCode = 0;
            if (OcspResp is not null)
            {
                hashCode = new BigInteger(OcspResp.GetSignature()).GetHashCode();
            }
                        
            result = prime * result + ((OcspResp == null) ? 0 : hashCode);
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
            OCSPRespToken other = (OCSPRespToken)obj;
            if (OcspResp == null)
            {
                if (other.OcspResp != null)
                {
                    return false;
                }
            }
            else
            {
                if (!this.GetHashCode().Equals(other.GetHashCode()))
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

        private X509Certificate? GetSigningCert()
        {
            IList<X509Certificate> certs = ((OCSPRespCertificateSource)GetWrappedCertificateSource()).GetCertificates(true);
            foreach (X509Certificate c in certs)
            {
                if (IsSignedBy(c))
                {
                    return c;
                }
            }

            nloglogger.Warn("Don't found an signer for OCSPToken in the " + certs.Count + " certificates " + certs);

            return null;
        }
    }
}
