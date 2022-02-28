using CAdESLib.Document.Validation;
using Org.BouncyCastle.X509;

namespace CAdESLib.Service
{
    public class AIACertificateFactoryImpl : ICertificateSourceFactory
    {
        private readonly IHTTPDataLoader httpDataLoader;

        /// <param name="httpDataLoader">the httpDataLoader to set</param>
        public AIACertificateFactoryImpl(IHTTPDataLoader httpDataLoader)
        {
            this.httpDataLoader = httpDataLoader;
        }

        public virtual ICertificateSource CreateAIACertificateSource(X509Certificate certificate)
        {
            return new AIACertificateSource(certificate, httpDataLoader);
        }
    }

}
