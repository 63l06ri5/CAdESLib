using CAdESLib.Helpers;
using NLog;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using System.Collections.Generic;
using System;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Abstract class that helps to implements OCSPSource with a already loaded list of BasicOCSPResp
    /// </summary>
    public abstract class OfflineOCSPSource : IOcspSource
    {
        private static readonly Logger nloglogger = LogManager.GetCurrentClassLogger();

        public bool TimestampsIncluded { get; set; } = false;

        public IEnumerable<BasicOcspResp?> GetOcspResponse(
                X509Certificate certificate,
                X509Certificate issuerCertificate,
                DateTime startDate,
                DateTime endDate)
        {
            nloglogger.Trace("try to find OCSP response. timestamps included: " + TimestampsIncluded);
            foreach (BasicOcspResp basicOCSPResp in GetOCSPResponsesFromSignature(false))
            {
                foreach (SingleResp singleResp in basicOCSPResp.Responses)
                {
                    var localCertId = singleResp.GetCertID();
                    CertificateID certId = new CertificateID(localCertId.HashAlgOid, issuerCertificate, certificate.SerialNumber);
                    if (localCertId.EqualsWithDerNull(certId))
                    {
                        nloglogger.Trace("OCSP response found");
                        yield return basicOCSPResp;
                    }
                }
            }
            OcspNotFound(certificate, issuerCertificate);
            yield return null;
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
        public abstract IList<BasicOcspResp> GetOCSPResponsesFromSignature(bool timestampIncluded);
    }
}
