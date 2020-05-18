using System;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Some certificate source are "offline", that means that the set of certificate is availaible and the software only
    /// needs to find the certificate on base of the subjectName
    /// </summary>
    public abstract class OfflineCertificateSource : ICertificateSource
    {
        private CertificateSourceType sourceType;

        /// <param>
        /// the sourceType to set
        /// </param>
        public virtual void SetSourceType(CertificateSourceType sourceType)
        {
            this.sourceType = sourceType;
        }

        public IList<CertificateAndContext> GetCertificateBySubjectName(X509Name subjectName)
        {
            IList<CertificateAndContext> list = new List<CertificateAndContext>();
            foreach (X509Certificate cert in GetCertificates())
            {
                if (subjectName.Equals(cert.SubjectDN))
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
