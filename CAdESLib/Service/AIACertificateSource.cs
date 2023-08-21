using CAdESLib.Document.Validation;
using CAdESLib.Helpers;
using NLog;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace CAdESLib.Service
{
    public class AIACertificateSource : ICertificateSource
    {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();
        private readonly ICAdESServiceSettings settings;
        private readonly X509Certificate certificate;

        private readonly Func<IHTTPDataLoader> httpDataLoaderFunc;

        /// <summary>The default constructor for AIACertificateSource.</summary>
        /// <remarks>The default constructor for AIACertificateSource.</remarks>
        public AIACertificateSource(X509Certificate certificate, Func<IHTTPDataLoader> httpDataLoaderFunc)
        {
            this.certificate = certificate;
            this.httpDataLoaderFunc = httpDataLoaderFunc;
        }

        public virtual IEnumerable<CertificateAndContext> GetCertificateBySubjectName(X509Name subjectName)
        {
            IList<CertificateAndContext> list = new List<CertificateAndContext>();
            try
            {
                string url = GetAccessLocation(certificate, X509ObjectIdentifiers.IdADCAIssuers);
                if (url != null)
                {
                    X509CertificateParser parser = new X509CertificateParser();
                    var response = httpDataLoaderFunc().Get(url);
                    if (response == null)
                    {
                        return list;
                    }

                    var bytes = GetBytes(response);
                    var certs = parser.ReadCertificates(bytes).Cast<X509Certificate>();

                    foreach (var cert in certs)
                    {
                        if (cert.SubjectDN.Equals(subjectName))
                        {
                            list.Add(new CertificateAndContext(cert));
                        }
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
            Asn1OctetString authInfoAccessExtensionValue = certificate.GetExtensionValue(Org.BouncyCastle.Asn1.X509.X509Extensions
                .AuthorityInfoAccess);
            if (null == authInfoAccessExtensionValue)
            {
                return null;
            }
            AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.GetInstance(authInfoAccessExtensionValue.GetOctets());
            AccessDescription[] accessDescriptions = authorityInformationAccess.GetAccessDescriptions();
            foreach (AccessDescription accessDescription in accessDescriptions)
            {
                logger.Trace("access method: " + accessDescription.AccessMethod);
                bool correctAccessMethod = accessDescription.AccessMethod.Equals(accessMethod);
                if (!correctAccessMethod)
                {
                    continue;
                }
                GeneralName gn = accessDescription.AccessLocation;
                if (gn.TagNo != GeneralName.UniformResourceIdentifier)
                {
                    logger.Trace("not a uniform resource identifier");
                    continue;
                }
                DerIA5String str = (DerIA5String) ((DerTaggedObject) gn.ToAsn1Object()).GetObject();
                string accessLocation = str.GetString();
                logger.Trace("access location: " + accessLocation);
                return accessLocation;
            }
            return null;
        }

        private byte[] GetBytes(Stream input)
        {
            using MemoryStream ms = new MemoryStream();

            input.CopyTo(ms);
            var bytes = ms.ToArray();

            try
            {
                return Convert.FromBase64String(Encoding.UTF8.GetString(bytes));
            }
            catch
            {
                return bytes;
            }
        }
    }

}
