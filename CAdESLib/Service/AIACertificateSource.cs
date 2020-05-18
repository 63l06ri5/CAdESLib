using System;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.X509;
using CAdESLib.Document.Signature;
using CAdESLib.Document.Validation;
using NLog;

namespace CAdESLib.Service
{
    public class AIACertificateSource : ICertificateSource
    {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        private readonly X509Certificate certificate;

        private readonly IHTTPDataLoader httpDataLoader;

        /// <summary>The default constructor for AIACertificateSource.</summary>
        /// <remarks>The default constructor for AIACertificateSource.</remarks>
        public AIACertificateSource(X509Certificate certificate, IHTTPDataLoader httpDataLoader)
        {
            this.certificate = certificate;
            this.httpDataLoader = httpDataLoader;
        }

        public virtual IList<CertificateAndContext> GetCertificateBySubjectName(X509Name
             subjectName)
        {
            IList<CertificateAndContext> list = new List<CertificateAndContext>();
            try
            {
                string url = GetAccessLocation(certificate, X509ObjectIdentifiers.IdADCAIssuers);
                if (url != null)
                {
                    X509CertificateParser parser = new X509CertificateParser();
                    X509Certificate cert = parser.ReadCertificate(httpDataLoader.Get(url));

                    if (cert.SubjectDN.Equals(subjectName))
                    {
                        list.Add(new CertificateAndContext(cert));
                    }
                }
            }
            catch (CannotFetchDataException)
            {
                return new List<CertificateAndContext>();
            }
            catch (CertificateException)
            {
                return new List<CertificateAndContext>();
            }
            return list;
        }

        private string GetAccessLocation(X509Certificate certificate, DerObjectIdentifier
             accessMethod)
        {
            Asn1OctetString authInfoAccessExtensionValue = certificate.GetExtensionValue(X509Extensions
                .AuthorityInfoAccess);
            if (null == authInfoAccessExtensionValue)
            {
                return null;
            }
            AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.GetInstance(authInfoAccessExtensionValue.GetOctets());
            AccessDescription[] accessDescriptions = authorityInformationAccess.GetAccessDescriptions();
            foreach (AccessDescription accessDescription in accessDescriptions)
            {
                logger.Info("access method: " + accessDescription.AccessMethod);
                bool correctAccessMethod = accessDescription.AccessMethod.Equals(accessMethod);
                if (!correctAccessMethod)
                {
                    continue;
                }
                GeneralName gn = accessDescription.AccessLocation;
                if (gn.TagNo != GeneralName.UniformResourceIdentifier)
                {
                    logger.Info("not a uniform resource identifier");
                    continue;
                }
                DerIA5String str = (DerIA5String)((DerTaggedObject)gn.ToAsn1Object()).GetObject();
                string accessLocation = str.GetString();
                logger.Info("access location: " + accessLocation);
                return accessLocation;
            }
            return null;
        }
    }

}
