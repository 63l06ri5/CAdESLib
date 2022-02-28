namespace CAdESLib.Document.Validation
{
    public abstract class SignatureLevel
    {
        private readonly SignatureValidationResult levelReached;

        public SignatureLevel(SignatureValidationResult levelReached)
        {
            this.levelReached = levelReached;
        }

        /// <returns>
        /// the levelReached
        /// </returns>
        public virtual SignatureValidationResult LevelReached => levelReached;
    }
}
