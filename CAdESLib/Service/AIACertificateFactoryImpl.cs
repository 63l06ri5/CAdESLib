using CAdESLib.Document.Validation;
using Org.BouncyCastle.X509;
using System;

namespace CAdESLib.Service
{
    public class AIACertificateFactoryImpl : ICertificateSourceFactory
    {
        private readonly Func<IHTTPDataLoader> httpDataLoaderFunc;

        /// <param name="httpDataLoaderFunc">the httpDataLoaderFunc to set</param>
        public AIACertificateFactoryImpl(Func<IHTTPDataLoader> httpDataLoaderFunc)
        {
            this.httpDataLoaderFunc = httpDataLoaderFunc;
        }

        public virtual ICertificateSource CreateAIACertificateSource(X509Certificate certificate)
        {
            return new AIACertificateSource(certificate, httpDataLoaderFunc);
        }
    }

}
