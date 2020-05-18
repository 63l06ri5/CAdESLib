using System;
using Org.BouncyCastle.X509;
using NLog;
using System.Threading;
using CAdESLib.Helpers;
using System.Collections.Generic;
using Org.BouncyCastle.Math;
using System.Linq;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Verify the status of a certificate using the Trusted List model.
    /// </summary>
    public class TrustedListCertificateVerifier : ICertificateVerifier
    {
        //private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        private Func<X509Certificate, DateTime, ICAdESLogger, IValidationContext> validationContextFactory;
        private List<IValidationContext> cache = new List<IValidationContext>();

        public TrustedListCertificateVerifier(Func<X509Certificate, DateTime, ICAdESLogger, IValidationContext> validationContextFactory)
        {
            this.validationContextFactory = validationContextFactory;
        }

        public virtual IValidationContext ValidateCertificate(
            X509Certificate cert, DateTime validationDate, ICertificateSource optionalCertificateSource, IList<CertificateAndContext> usedCerts, ICrlSource optionalCRLSource = null, IOcspSource optionalOCSPSource = null, ICAdESLogger CadesLogger = null)
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
             
            var context = validationContextFactory(cert, validationDate, CadesLogger);
            context.Validate(validationDate, optionalCertificateSource, optionalCRLSource, optionalOCSPSource, usedCerts);
            cache.Add(context);

            return context;
        }
    }
}
