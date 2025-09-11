using NLog;
using Org.BouncyCastle.X509;
using System.Collections.Generic;
using System;

namespace CAdESLib.Document.Validation
{
    public class CompositeCrlSource : ICrlSource
    {
        private static readonly Logger nloglogger = LogManager.GetCurrentClassLogger();
        
        private readonly ICrlSource?[] sources;

        public CompositeCrlSource(params ICrlSource?[] sources)
        {
            this.sources = sources;
        }

        public IEnumerable<X509Crl> FindCrls(
                X509Certificate certificate,
                X509Certificate issuerCertificate,
                DateTime startDate,
                DateTime endDate)
        {
            foreach (var source in sources)
            {
                if (source != null)
                {
                    var @internal = source.FindCrls(certificate, issuerCertificate, startDate, endDate);
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
