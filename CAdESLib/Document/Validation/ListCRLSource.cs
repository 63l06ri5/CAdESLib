using System;
using System.Collections.Generic;
using Org.BouncyCastle.X509;

namespace CAdESLib.Document.Validation
{
    public class ListCRLSource : OfflineCRLSource
    {
        private readonly IList<X509Crl> list;

        public ListCRLSource(IList<X509Crl> list)
        {
            this.list = list;
        }

        public override IList<X509Crl> GetCRLsFromSignature()
        {
            return list;
        }
    }
}
