using Org.BouncyCastle.Asn1.X509;
using System.Collections.Generic;

namespace CAdESLib.Document.Validation
{
    public class CompositeCertificateSource : ICertificateSource
    {
        private readonly ICertificateSource?[] sources;

        public CompositeCertificateSource(params ICertificateSource?[] sources)
        {
            this.sources = sources;
        }

        public virtual IEnumerable<CertificateAndContext> GetCertificateBySubjectName(X509Name? subjectName)
        {
            foreach (var source in sources)
            {
                if (source != null)
                {
                    var @internal = source.GetCertificateBySubjectName(subjectName);
                    if (@internal != null)
                    {
                        foreach (var item in @internal)
                        {
                            yield return item;
                        }
                    }
                }
            }
        }
    }
}
