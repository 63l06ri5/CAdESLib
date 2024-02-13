using CAdESLib.Helpers;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;

namespace CAdESLib.Document.Validation
{
    public interface ICertificateVerifier
    {
        /// <summary>
        /// Return a ValidationContext that contains every information available to validate a X509 Certificate.
        /// </summary>
        IValidationContext GetValidationContext(X509Certificate cert, DateTime validationDate, ICAdESLogger? CadesLogger = null);
    }
}
