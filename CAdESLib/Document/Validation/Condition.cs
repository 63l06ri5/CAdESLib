using System;
using System.Collections.Generic;
using System.Text;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Represents a condition on a certificate
    /// </summary>
    public interface Condition
    {
        /// <summary>
        /// Return true if the condition evaluate to true
        /// </summary>
        bool Check(CertificateAndContext cert);
    }
}
