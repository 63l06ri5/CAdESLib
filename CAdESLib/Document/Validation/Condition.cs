namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Represents a condition on a certificate
    /// </summary>
    public interface ICondition
    {
        /// <summary>
        /// Return true if the condition evaluate to true
        /// </summary>
        bool Check(CertificateAndContext cert);
    }
}
