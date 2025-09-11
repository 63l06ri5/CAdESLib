using System;
using CAdESLib.Document.Signature;
using CAdESLib.Document.Validation;
using CAdESLib.Service;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.X509;
using Unity;
using Unity.Lifetime;

namespace CAdESLib.Helpers
{
    public static class CAdESServiceImpl
    {
        public static IUnityContainer DefaultCAdESLibSetup(this IUnityContainer container)
        {
            return container
               .RegisterType<ICurrentTimeGetter, CurrentTimeGetter>()
               .RegisterType<ICAdESServiceSettings, CAdESServiceSettings>(new ContainerControlledLifetimeManager())
               .RegisterFactory<Func<IRuntimeValidatingParams, IHTTPDataLoader>>(
                   c => new Func<IRuntimeValidatingParams, IHTTPDataLoader>(
                       (runtimeValidatingParams) => new NetHttpDataLoader(runtimeValidatingParams)))

               // CAdESLib usage
               .RegisterType<ICryptographicProvider, BouncyCastleCryptographicProvider>()

               .RegisterFactory<Func<ICAdESServiceSettings, IDocumentSignatureService>>(c => new Func<ICAdESServiceSettings, IDocumentSignatureService>(
                   (settings) => new CAdESService(
                       (runtimeValidatingParams) => c.Resolve<Func<IRuntimeValidatingParams, ICAdESServiceSettings, ITspSource>>()(runtimeValidatingParams, settings),
                       (runtimeValidatingParams) => c.Resolve<Func<IRuntimeValidatingParams, ICAdESServiceSettings, ICertificateVerifier>>()(runtimeValidatingParams, settings),
                       (runtimeValidatingParams) => c.Resolve<Func<IRuntimeValidatingParams, ICAdESServiceSettings, ISignedDocumentValidator>>()(runtimeValidatingParams, settings),
                       c.Resolve<ICryptographicProvider>(),
                       c.Resolve<ICurrentTimeGetter>())
                   ))

               .RegisterFactory<Func<IRuntimeValidatingParams, ICAdESServiceSettings, ICertificateVerifier>>(c => new Func<IRuntimeValidatingParams, ICAdESServiceSettings, ICertificateVerifier>((runtimeValidationSettings, settings) =>
                   new TrustedListCertificateVerifier(
                        c.Resolve<Func<IRuntimeValidatingParams, ICAdESServiceSettings, Func<X509Certificate, ICAdESLogger, IValidationContext>>>()(runtimeValidationSettings, settings),
                        c.Resolve<ICAdESLogger>())
                   ))

               .RegisterFactory<Func<IRuntimeValidatingParams, ICAdESServiceSettings, ISignedDocumentValidator>>(c => new Func<IRuntimeValidatingParams, ICAdESServiceSettings, ISignedDocumentValidator>((runtimeValidationSettings, settings) =>
                   new SignedDocumentValidator(
                       c.Resolve<Func<IRuntimeValidatingParams, ICAdESServiceSettings, ICertificateVerifier>>()(runtimeValidationSettings, settings),
                       c.Resolve<Func<ICAdESLogger>>(),
                       c.Resolve<Func<IRuntimeValidatingParams, ICAdESServiceSettings,
                       Func<X509Certificate, ICAdESLogger, IValidationContext>>>()(runtimeValidationSettings, settings),
                       c.Resolve<ICryptographicProvider>(),
                       c.Resolve<ICurrentTimeGetter>())))

               .RegisterType<ICAdESLogger, CAdESLogger>(new TransientLifetimeManager())

               .RegisterFactory<Func<IRuntimeValidatingParams, ICAdESServiceSettings, ITspSource>>(
                   c =>
                   new Func<IRuntimeValidatingParams, ICAdESServiceSettings, ITspSource>(
                       (runtimeValidatingParams, settings) =>
                           new OnlineTspSource(
                               settings,
                               () => c.Resolve<Func<IRuntimeValidatingParams, IHTTPDataLoader>>()(runtimeValidatingParams))))

               .RegisterFactory<Func<IRuntimeValidatingParams, ICAdESServiceSettings, IOcspSource>>(
                   c =>
                   new Func<IRuntimeValidatingParams, ICAdESServiceSettings, IOcspSource>(
                       (runtimeValidatingParams, settings) =>
                       new OnlineOcspSource(
                           settings,
                           () => c.Resolve<Func<IRuntimeValidatingParams, IHTTPDataLoader>>()(runtimeValidatingParams))))

               .RegisterFactory<Func<IRuntimeValidatingParams, ICAdESServiceSettings, ICrlSource>>(
                   c =>
                   new Func<IRuntimeValidatingParams, ICAdESServiceSettings, ICrlSource>(
                       (runtimeValidatingParams, settings) =>
                       new OnlineCrlSource(
                           settings,
                           () => c.Resolve<Func<IRuntimeValidatingParams, IHTTPDataLoader>>()(runtimeValidatingParams))))

               .RegisterFactory<Func<ICAdESServiceSettings, ICertificateSource>>(c => new Func<ICAdESServiceSettings, ICertificateSource>((settings) => new ListCertificateSourceWithSetttings(settings)))

               .RegisterFactory<Func<IRuntimeValidatingParams, ICertificateSourceFactory>>(
                   c =>
                   new Func<IRuntimeValidatingParams, ICertificateSourceFactory>(
                       (runtimeValidatingParams) =>
                           new AIACertificateFactoryImpl(
                               () => c.Resolve<Func<IRuntimeValidatingParams, IHTTPDataLoader>>()(runtimeValidatingParams))))

               .RegisterFactory<Func<IRuntimeValidatingParams, ICAdESServiceSettings, Func<X509Certificate, ICAdESLogger, IValidationContext>>>(
                   c =>
                   new Func<IRuntimeValidatingParams, ICAdESServiceSettings, Func<X509Certificate, ICAdESLogger, IValidationContext>>(
                       (runtimeValidatingParams, settings) => (cert, logger) =>
                       new ValidationContext(
                             cert,
                             logger,
                             c.Resolve<Func<IRuntimeValidatingParams, ICAdESServiceSettings, IOcspSource>>()(runtimeValidatingParams, settings),
                             c.Resolve<Func<IRuntimeValidatingParams, ICAdESServiceSettings, ICrlSource>>()(runtimeValidatingParams, settings),
                             c.Resolve<Func<ICAdESServiceSettings, ICertificateSource>>()(settings),
                             c.Resolve<Func<IRuntimeValidatingParams, Func<CmsSignedData, IOcspSource, ICrlSource, ICertificateStatusVerifier>>>()(runtimeValidatingParams),
                             (context) => c.Resolve<Func<IRuntimeValidatingParams, CertificateAndContext, CertificateToken>>()(runtimeValidatingParams, context))
                       ))
               .RegisterFactory<Func<IRuntimeValidatingParams, Func<CmsSignedData, IOcspSource, ICrlSource, ICertificateStatusVerifier>>>(
                   c =>
                   new Func<IRuntimeValidatingParams, Func<CmsSignedData, IOcspSource, ICrlSource, ICertificateStatusVerifier>>(
                       (runtimeParams) => (cms, ocspVerifier, crlVerifier) =>
                        new OCSPAndCRLCertificateVerifier(
                            cms,
                            new OCSPCertificateVerifier(ocspVerifier),
                            new CRLCertificateVerifier(crlVerifier),
                            runtimeParams,
                            c.Resolve<ICryptographicProvider>()))
               )
               .RegisterFactory<Func<IRuntimeValidatingParams, CertificateAndContext, CertificateToken>>(
                   c =>
                   new Func<IRuntimeValidatingParams, CertificateAndContext, CertificateToken>(
                       (runtimeValidatingParams, context) =>
                           new CertificateToken(context, c.Resolve<Func<IRuntimeValidatingParams, ICertificateSourceFactory>>()(runtimeValidatingParams))))

               ;

        }
    }
}
