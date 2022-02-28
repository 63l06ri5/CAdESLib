using Org.BouncyCastle.Ocsp;
using System.Collections.Generic;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Implement a OCSPSource from a List of BasicOCSPResp
    /// </summary>
    public class ListOCSPSource : OfflineOCSPSource
    {
        private readonly IList<BasicOcspResp> ocsps;

        public ListOCSPSource(IList<BasicOcspResp> ocsps)
        {
            this.ocsps = ocsps;
        }

        public override IList<BasicOcspResp> GetOCSPResponsesFromSignature()
        {
            return ocsps;
        }
    }
}
