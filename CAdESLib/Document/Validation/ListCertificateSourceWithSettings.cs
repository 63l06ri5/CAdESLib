﻿using CAdESLib.Helpers;
using Org.BouncyCastle.X509;
using System.Collections.Generic;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Create a CertificateSource from a List or Array of Certificate.
    /// </summary>
    public class ListCertificateSourceWithSetttings : OfflineCertificateSource
    {
        private readonly ICAdESServiceSettings settings;

        public ListCertificateSourceWithSetttings(ICAdESServiceSettings settings)
        {
            this.settings = settings;
            this.SetSourceType(CertificateSourceType.TRUSTED_LIST);
        }

        public override IList<X509Certificate> GetCertificates()
        {
            return settings.TrustedCerts ?? new List<X509Certificate>();
        }
    }
}
