using NLog;
using Org.BouncyCastle.X509;
using System.Collections.Generic;

namespace CAdESLib.Document.Validation
{
    public abstract class OfflineCRLSource : ICrlSource
    {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        public IEnumerable<X509Crl> FindCrls(X509Certificate certificate, X509Certificate issuerCertificate)
        {
            var crls = new List<X509Crl>();
            foreach (X509Crl crl in GetCRLsFromSignature())
            {
                if (crl.IssuerDN.Equals(issuerCertificate.SubjectDN))
                {
                    logger.Info("CRL found for issuer " + issuerCertificate.SubjectDN.ToString());
                    crls.Add(crl);
                }
            }
            return crls;
        }

        /// <summary>
        /// Retrieve the list of CRL contained in the Signature
        /// </summary>
        public abstract IList<X509Crl> GetCRLsFromSignature();
    }
}
