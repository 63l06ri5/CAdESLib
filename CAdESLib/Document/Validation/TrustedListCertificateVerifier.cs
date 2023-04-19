using CAdESLib.Helpers;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.ConstrainedExecution;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Verify the status of a certificate using the Trusted List model.
    /// </summary>
    public class TrustedListCertificateVerifier : ICertificateVerifier
    {
        //private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        private readonly Func<X509Certificate, DateTime, ICAdESLogger, IValidationContext> validationContextFactory;
        private readonly List<IValidationContext> cache = new List<IValidationContext>();

        public TrustedListCertificateVerifier(Func<X509Certificate, DateTime, ICAdESLogger, IValidationContext> validationContextFactory)
        {
            this.validationContextFactory = validationContextFactory;
        }

        public IValidationContext GetValidationContext(X509Certificate cert, DateTime validationDate, ICAdESLogger CadesLogger = null)
        {
            if (cert == null || validationDate == null)
            {
                throw new ArgumentNullException("A validation context must contains a cert and a validation date");
            }

            var alreadyUsed = cache.FirstOrDefault(x => x.Certificate == cert && x.ValidationDate == validationDate);
            if (alreadyUsed != null)
            {
                return alreadyUsed;
            }

            IValidationContext context = validationContextFactory(cert, validationDate, CadesLogger);
            cache.Add(context);

            return context;
        }
    }
}
