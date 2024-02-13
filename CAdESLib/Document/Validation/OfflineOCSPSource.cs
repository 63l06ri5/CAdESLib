using CAdESLib.Helpers;
using NLog;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using System.Collections.Generic;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Abstract class that helps to implements OCSPSource with a already loaded list of BasicOCSPResp
    /// </summary>
    public abstract class OfflineOCSPSource : IOcspSource
    {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        public BasicOcspResp? GetOcspResponse(X509Certificate certificate, X509Certificate
             issuerCertificate)
        {
            logger.Trace("find OCSP response");
            try
            {
                foreach (BasicOcspResp basicOCSPResp in GetOCSPResponsesFromSignature())
                {
                    foreach (SingleResp singleResp in basicOCSPResp.Responses)
                    {
                        var localCertId = singleResp.GetCertID();
                        CertificateID certId = new CertificateID(localCertId.HashAlgOid, issuerCertificate, certificate.SerialNumber);
                        if (localCertId.EqualsWithDerNull(certId))
                        {
                            logger.Trace("OCSP response found");
                            return basicOCSPResp;
                        }
                    }
                }
                OcspNotFound(certificate, issuerCertificate);
                return null;
            }
            catch (OcspException e)
            {
                logger.Error("OcspException: " + e.Message);
                return null;
            }
        }

        /// <summary>
        /// Callback used when the OCSP is not found.
        /// </summary>
        public virtual void OcspNotFound(X509Certificate certificate, X509Certificate issuerCertificate)
        {
        }

        /// <summary>
        /// Retrieve the list of BasicOCSPResp contained in the Signature.
        /// </summary>
        public abstract IList<BasicOcspResp> GetOCSPResponsesFromSignature();
    }
}
