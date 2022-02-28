namespace CAdESLib.Document.Validation
{
    public class QualificationElement
    {
        public QualificationElement(string qualification, ICondition condition)
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
        public virtual ICondition Condition { get; set; }
    }
}
