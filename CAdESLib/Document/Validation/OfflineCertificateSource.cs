using NLog;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using System.Collections.Generic;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Some certificate source are "offline", that means that the set of certificate is availaible and the software only
    /// needs to find the certificate on base of the subjectName
    /// </summary>
    public abstract class OfflineCertificateSource : ICertificateSource
    {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        private CertificateSourceType sourceType;

        /// <param>
        /// the sourceType to set
        /// </param>
        public virtual void SetSourceType(CertificateSourceType sourceType)
        {
            this.sourceType = sourceType;
        }

        public IEnumerable<CertificateAndContext> GetCertificateBySubjectName(X509Name? subjectName)
        {
            IList<CertificateAndContext> list = new List<CertificateAndContext>();
            foreach (X509Certificate cert in GetCertificates())
            {
                if (subjectName == null || subjectName.Equals(cert.SubjectDN))
                {
                    CertificateAndContext cc = new CertificateAndContext(cert)
                    {
                        CertificateSource = sourceType
                    };
                    list.Add(cc);
                }
            }
            return list;
        }

        /// <summary>
        /// Retrieve the list of certificate from this source.
        /// </summary>
        public abstract IList<X509Certificate> GetCertificates();
    }
}
