using CAdESLib.Helpers;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Linq;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Verify the status of a certificate using the Trusted List model.
    /// </summary>
    public class TrustedListCertificateVerifier : ICertificateVerifier
    {
        private readonly Func<X509Certificate, ICAdESLogger, IValidationContext> validationContextFactory;
        private readonly List<IValidationContext> cache = new List<IValidationContext>();
        private readonly ICAdESLogger CadesLogger;

        public TrustedListCertificateVerifier(Func<X509Certificate, ICAdESLogger, IValidationContext> validationContextFactory, ICAdESLogger cadesLogger)
        {
            this.validationContextFactory = validationContextFactory;
            this.CadesLogger = cadesLogger;
        }

        public IValidationContext GetValidationContext(X509Certificate cert)
        {
            if (cert == null)
            {
                throw new ArgumentNullException("A validation context must contains a cert");
            }

            var alreadyUsed = cache.FirstOrDefault(x => x.Certificate == cert);
            if (alreadyUsed != null)
            {
                return alreadyUsed;
            }

            IValidationContext context = validationContextFactory(cert, CadesLogger);
            cache.Add(context);

            return context;
        }
    }
}
