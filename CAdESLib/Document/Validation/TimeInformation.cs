using System;
using System.Collections.Generic;
using System.Text;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Information about the time of validation.
    /// </summary>
    public class TimeInformation
    {
        private readonly DateTime verificationTime;

        /// <returns>
        /// the verificationTime
        /// </returns>
        public virtual DateTime VerificationTime => verificationTime;

        public TimeInformation(DateTime verificationTime)
        {
            this.verificationTime = verificationTime;
        }
    }
}
