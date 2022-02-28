using System.ComponentModel;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Representation of the Result in the validation report.
    /// </summary>
    public class SignatureValidationResult
    {
        /// <summary>
        /// Supported values
        /// </summary>
        public enum ResultStatus
        {

            [Description("$UI_Signatures_ValidationStatus_Valid")]
            VALID,
            [Description("$UI_Signatures_ValidationStatus_Invalid")]
            INVALID,
            [Description("$UI_Signatures_ValidationStatus_Undetermined")]
            UNDETERMINED,
            [Description("$UI_Signatures_ValidationStatus_ValidWarnings")]
            VALID_WITH_WARNINGS,
            [Description("$UI_Signatures_ValidationStatus_Information")]
            INFORMATION
        }

        private ResultStatus status;

        protected internal string description;

        public SignatureValidationResult(ResultStatus status, string description)
        {
            this.status = status;
            this.description = description;
        }

        public SignatureValidationResult() : this(ResultStatus.UNDETERMINED, null)
        {
        }

        /// <summary>
        /// One-liner to create a Result by asserting something
        /// </summary>
        /// <param>
        /// the status to set if the test fails
        /// </param>
        private SignatureValidationResult(bool assertion, ResultStatus statusIfFailed) : this()
        {
            if (assertion)
            {
                SetStatus(ResultStatus.VALID, null);
            }
            else
            {
                SetStatus(statusIfFailed, null);
            }
        }

        /// <summary>
        /// One-liner to create a Result by asserting something, set to invalid if the assertion fails
        /// </summary>
        public SignatureValidationResult(bool assertion) : this(assertion, ResultStatus.INVALID)
        {
        }

        public override string ToString()
        {
            return "Result[" + status + "]";
        }

        /// <summary>
        /// returns whether the check was valid
        /// </summary>
        /// <returns>
        /// true if valid
        /// </returns>
        public virtual bool IsValid => (Status == ResultStatus.VALID);

        /// <summary>
        /// returns whether the check was invalid
        /// </summary>
        /// <returns>
        /// true if valid
        /// </returns>
        public virtual bool IsInvalid => (Status == ResultStatus.INVALID);

        /// <summary>
        /// returns whether the check was undetermined
        /// </summary>
        /// <returns>
        /// true if undetermined
        /// </returns>
        public virtual bool IsUndetermined => (Status == ResultStatus.UNDETERMINED);

        /// <param name="status"></param>
        public virtual void SetStatus(ResultStatus status, string description)
        {
            this.status = status;
            this.description = description;
        }

        /// <summary>
        /// Set description of the result
        /// </summary>
        /// <param name="description"></param>
        public virtual void SetDescription(string description)
        {
            this.description = description;
        }

        /// <returns>
        /// the result
        /// </returns>
        public virtual ResultStatus Status => status;

        /// <returns>
        /// the description
        /// </returns>
        public virtual string Description => description;
    }
}
