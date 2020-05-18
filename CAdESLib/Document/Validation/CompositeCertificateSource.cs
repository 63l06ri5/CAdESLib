using Org.BouncyCastle.Asn1.X509;
using System;
using System.Collections.Generic;
using System.Text;

namespace CAdESLib.Document.Validation
{
    public class CompositeCertificateSource : ICertificateSource
    {
        private readonly ICertificateSource[] sources;

        public CompositeCertificateSource(params ICertificateSource[] sources)
        {
            this.sources = sources;
        }

        public virtual IList<CertificateAndContext> GetCertificateBySubjectName(X509Name
             subjectName)
        {
            List<CertificateAndContext> list = new List<CertificateAndContext>();
            foreach (ICertificateSource source in sources)
            {
                if (source != null)
                {
                    IList<CertificateAndContext> @internal = source.GetCertificateBySubjectName(subjectName);
                    if (@internal != null)
                    {
                        list.AddRange(@internal);
                    }
                }
            }
            return list;
        }
    }
}
