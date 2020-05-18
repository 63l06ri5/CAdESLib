using System;
using System.Collections.Generic;
using Org.BouncyCastle.X509;
using NLog;

namespace CAdESLib.Document.Validation
{
    public abstract class OfflineCRLSource : ICrlSource
    {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        public X509Crl FindCrl(X509Certificate certificate, X509Certificate issuerCertificate)
        {
            foreach (X509Crl crl in GetCRLsFromSignature())
            {
                if (crl.IssuerDN.Equals(issuerCertificate.SubjectDN))
                {
                    logger.Info("CRL found for issuer " + issuerCertificate.SubjectDN.ToString());
                    return crl;
                }
            }
            logger.Info("CRL not found for issuer " + issuerCertificate.SubjectDN.ToString());
            return null;
        }

        /// <summary>
        /// Retrieve the list of CRL contained in the Signature
        /// </summary>
        public abstract IList<X509Crl> GetCRLsFromSignature();
    }
}
