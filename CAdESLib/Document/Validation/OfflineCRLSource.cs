using NLog;
using Org.BouncyCastle.X509;
using System.Collections.Generic;
using System;

namespace CAdESLib.Document.Validation
{
    public abstract class OfflineCRLSource : ICrlSource
    {
        private static readonly Logger nloglogger = LogManager.GetCurrentClassLogger();
        
        public bool TimestampsIncluded { get; set; } = false;

        public IEnumerable<X509Crl> FindCrls(
                X509Certificate certificate,
                X509Certificate issuerCertificate,
                DateTime startDate,
                DateTime endDate)
        {
            nloglogger.Trace("try to find CRLs. timestamps included: " + TimestampsIncluded);
            foreach (X509Crl crl in GetCRLsFromSignature(TimestampsIncluded))
            {
                if (crl.IssuerDN.Equals(issuerCertificate.SubjectDN))
                {
                    nloglogger.Trace("CRL found for issuer " + issuerCertificate.SubjectDN.ToString());
                    yield return crl;
                }
            }
        }

        /// <summary>
        /// Retrieve the list of CRL contained in the Signature
        /// </summary>
        public abstract IList<X509Crl> GetCRLsFromSignature(bool timestampIncluded);
    }
}
