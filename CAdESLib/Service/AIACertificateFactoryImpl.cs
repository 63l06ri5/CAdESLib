using Org.BouncyCastle.X509;
using CAdESLib.Document.Validation;

namespace CAdESLib.Service
{
    public class AIACertificateFactoryImpl : ICertificateSourceFactory
    {
        private IHTTPDataLoader httpDataLoader;

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
