using NLog;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using System.Collections.Generic;
using System;

namespace CAdESLib.Document.Validation
{
    public class CompositeOcspSource : IOcspSource
    {
        private static readonly Logger nloglogger = LogManager.GetCurrentClassLogger();

        private readonly IOcspSource?[] sources;

        public CompositeOcspSource(params IOcspSource?[] sources)
        {
            this.sources = sources;
        }

        public IEnumerable<BasicOcspResp?> GetOcspResponse(
                X509Certificate certificate,
                X509Certificate issuerCertificate,
                DateTime startDate,
                DateTime endDate)
        {
            foreach (var source in sources)
            {
                if (source != null)
                {
                    foreach(var resp in  source.GetOcspResponse(certificate, issuerCertificate, startDate, endDate))
                    {
                        yield return resp;
                    }
                }
            }
        }
    }
}
