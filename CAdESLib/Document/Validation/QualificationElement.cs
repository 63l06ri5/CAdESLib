using System;
using System.Collections.Generic;
using System.Text;

namespace CAdESLib.Document.Validation
{
    public class QualificationElement
    {
        public QualificationElement(string qualification, Condition condition)
        {
            this.Qualification = qualification;
            this.Condition = condition;
        }

        /// <returns>
        /// the qualification
        /// </returns>
        public virtual string Qualification { get; set; }

        /// <returns>
        /// the condition
        /// </returns>
        public virtual Condition Condition { get; set; }
    }
}
