using NLog;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using System.Collections.Generic;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Implement a CertificateSource that retrieve the certificates from an OCSPResponse
    /// </summary>
    public class OCSPRespCertificateSource : OfflineCertificateSource
    {
        private static readonly Logger nloglogger = LogManager.GetCurrentClassLogger();

        private readonly BasicOcspResp ocspResp;

        public OCSPRespCertificateSource(BasicOcspResp ocspResp)
        {
            this.ocspResp = ocspResp;
        }

        public override IList<X509Certificate> GetCertificates(bool timestampIncluded)
        {
            IList<X509Certificate> certs = new List<X509Certificate>();
            foreach (X509Certificate c in ocspResp.GetCerts())
            {
                certs.Add(c);
            }
            return certs;
        }
    }
}
