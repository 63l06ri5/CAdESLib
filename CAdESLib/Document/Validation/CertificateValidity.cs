using System;
using System.Collections.Generic;
using System.Text;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Possible Revocation value for a certificate
    /// </summary>
    public enum CertificateValidity
    {
        VALID,
        REVOKED,
        UNKNOWN
    }
}
