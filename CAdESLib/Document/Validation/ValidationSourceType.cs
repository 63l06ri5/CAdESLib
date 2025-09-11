namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Possible source of a revocation data.
    /// </summary>
    public enum ValidatorSourceType
    {
        CRL,
        OCSP,
        TRUSTED_LIST,
        SELF_SIGNED,
        OCSP_NO_CHECK,
        NOT_TRUSTED_LIST
    }
}
