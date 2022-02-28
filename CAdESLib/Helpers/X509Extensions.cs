using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using SystemX509 = System.Security.Cryptography.X509Certificates;

namespace CAdESLib.Helpers
{
    public static class X509Extensions
    {
        public static X509Certificate[] GetCertificateChain(this SystemX509.X509Certificate2 cert2)
        {
            List<X509Certificate> list = new List<X509Certificate>();

            SystemX509.X509Chain chain = new SystemX509.X509Chain();

            chain.ChainPolicy.RevocationFlag = SystemX509.X509RevocationFlag.EntireChain;
            chain.ChainPolicy.RevocationMode = SystemX509.X509RevocationMode.Online;
            chain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(0, 0, 30);
            chain.ChainPolicy.VerificationFlags = SystemX509.X509VerificationFlags.NoFlag;

            if (chain.Build(cert2) == true)
            {
                foreach (SystemX509.X509ChainElement element in chain.ChainElements)
                {
                    list.Add(new X509CertificateParser().ReadCertificate(element.Certificate.GetRawCertData()));
                }
            }
            else
            {
                list.Add(new X509CertificateParser().ReadCertificate(cert2.GetRawCertData()));
            }

            return list.ToArray();
        }
    }
}
