using NLog;
using Org.BouncyCastle.X509;
using System.Collections.Generic;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Create a CertificateSource from a List or Array of Certificate.
    /// </summary>
    public class ListCertificateSource : OfflineCertificateSource
    {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        private readonly IList<X509Certificate> certificates;

        public ListCertificateSource(IList<X509Certificate> certificates)
        {
            this.certificates = certificates;
        }

        public ListCertificateSource(X509Certificate[] certificates)
            : this(new List<X509Certificate>(certificates))
        {
        }

        public override IList<X509Certificate> GetCertificates()
        {
            return certificates;
        }
    }
}
