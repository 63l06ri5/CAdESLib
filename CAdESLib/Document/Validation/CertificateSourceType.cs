using System;
using System.Collections.Generic;
using System.Text;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Standard sources for a certificate
    /// </summary>
    public enum CertificateSourceType
    {
        TRUST_STORE,
        TRUSTED_LIST,
        SIGNATURE
    }
}
