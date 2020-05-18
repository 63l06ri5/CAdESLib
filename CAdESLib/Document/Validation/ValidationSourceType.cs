using System;
using System.Collections.Generic;
using System.Text;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Possible source of a revocation data.
    /// </summary>
    public enum ValidatorSourceType
    {
        CRL,
        OCSP,
        TRUSTED_LIST,
        SELF_SIGNED
    }
}
