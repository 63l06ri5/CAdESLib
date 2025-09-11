using System;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// RevocationData for a specific ISignedToken
    /// </summary>
    public class RevocationData
    {
        private readonly ISignedToken targetToken;

        public RevocationData(ISignedToken signedToken)
        {
            targetToken = signedToken;
        }
        public CertificateAndContext? RevocationDataAsCertificate { get; set; }
        public StatusSource? RevocationDataAsStatusSource { get; set; }
        public CertificateSourceType? RevocationDataAsCertificateSourceType { get; set; }


        /// <summary>
        /// The target of this revocation data
        /// </summary>
        public ISignedToken TargetToken
        {
            get { return targetToken; }
        }

        public bool Processed => RevocationDataAsStatusSource is not null ||
            RevocationDataAsCertificate is not null ||
            RevocationDataAsCertificateSourceType is not null;

        /// <summary>
        /// The value of the revocation data
        /// </summary>
        public virtual StatusSource? GetRevocationDataStatusFor(DateTime startDate, DateTime endDate)
        {
            if (this.RevocationDataAsStatusSource?.IsValidForTime(startDate, endDate) ?? false)
            {
                return this.RevocationDataAsStatusSource;
            }
            return null;
        }

        public override string ToString()
        {
            string data;
            if (RevocationDataAsCertificate is not null)
            {
                data = "Certificate[subjectName=" + RevocationDataAsCertificate.Certificate.SubjectDN + "]";
            }
            else if (RevocationDataAsStatusSource is not null)
            {
                data = string.Join(", ", RevocationDataAsStatusSource.Source?.GetType().ToString() ?? "null");
            }
            else if (RevocationDataAsCertificateSourceType is not null)
            {
                data = RevocationDataAsCertificateSourceType.ToString()!;
            }
            else
            {
                data = "*** NO VALIDATION DATA AVAILABLE ***";
            }
            return "RevocationData[token=" + targetToken + ",data=" + data + "]";
        }
    }
}
