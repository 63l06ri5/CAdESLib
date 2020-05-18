using System;
using System.Collections.Generic;
using System.Text;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// The advanced signature contains a list of certificate that was needed to validate the signature.
    /// </summary>
    /// <remarks>
    /// The advanced signature contains a list of certificate that was needed to validate the signature. This class if a
    /// basic skeleton that is able to retrieve the needed certificate from a list. The child need to retrieve the list of
    /// wrapped certificates.
    /// </remarks>
    public abstract class SignatureCertificateSource : OfflineCertificateSource
    {
    }
}
