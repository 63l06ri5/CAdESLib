using System;
using CAdESLib.Document.Signature;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Information for all the levels of the signature.
    /// </summary>
    public class SignatureLevelAnalysis
    {
        private readonly IAdvancedSignature signature;

        private readonly SignatureLevelBES levelBES;

        private readonly SignatureLevelEPES levelEPES;

        private readonly SignatureLevelT levelT;

        private readonly SignatureLevelC levelC;

        private readonly SignatureLevelX levelX;

        private readonly SignatureLevelXL levelXL;

        private readonly SignatureLevelA levelA;


        public SignatureLevelAnalysis(IAdvancedSignature signature, SignatureLevelBES levelBES, SignatureLevelEPES levelEPES, SignatureLevelT levelT, SignatureLevelC levelC,
            SignatureLevelX levelX, SignatureLevelXL levelXL, SignatureLevelA levelA)
        {
            bool levelReached = true;
            this.signature = signature;
            this.levelBES = levelBES;
            bool levelBESReached = LevelIsReached(levelBES, levelReached);
            levelReached = levelBESReached;
            this.levelEPES = levelEPES;
            LevelIsReached(levelEPES, levelReached);
            this.levelT = levelT;
            bool levelReachedT = LevelIsReached(levelT, levelReached);
            this.levelC = levelC;
            levelReached = LevelIsReached(levelC, levelReachedT);
            this.levelX = levelX;
            levelReached = LevelIsReached(levelX, levelReached);
            this.levelXL = levelXL;
            levelReached = LevelIsReached(levelXL, levelReached);
            this.levelA = levelA;
            levelReached = LevelIsReached(levelA, levelReached);
        }

        private bool LevelIsReached(SignatureLevel level, bool previousLevel)
        {
            if (level != null)
            {
                if (!previousLevel)
                {
                    level.LevelReached.SetStatus(SignatureValidationResult.ResultStatus.INVALID, "$UI_Signatures_ValidationText_PreviousLevelHasErrors");
                }
                bool thisLevel = previousLevel && level.LevelReached.IsValid;
                return thisLevel;
            }
            else
            {
                return false;
            }
        }

        /// <returns>
        /// the signatureFormat
        /// </returns>
        public virtual string SignatureFormat
        {
            get
            {
                string signatureFormat = null;
                if (signature is CAdESSignature)
                {
                    signatureFormat = "PAdES";
                }
                else
                {
                    throw new InvalidOperationException("Unsupported IAdvancedSignature " + signature.
                        GetType().FullName);
                }
                return signatureFormat;
            }
        }

        /// <returns>
        /// the signature
        /// </returns>
        public virtual IAdvancedSignature Signature => signature;

        /// <summary>
        /// Get report for level BES
        /// </summary>
        /// <returns></returns>
        public virtual SignatureLevelBES LevelBES => levelBES;

        /// <summary>
        /// Get report for level EPES
        /// </summary>
        /// <returns></returns>
        public virtual SignatureLevelEPES LevelEPES => levelEPES;

        /// <summary>
        /// Get report for level T
        /// </summary>
        /// <returns></returns>
        public virtual SignatureLevelT LevelT => levelT;

        /// <summary>
        /// Get report for level C
        /// </summary>
        /// <returns></returns>
        public virtual SignatureLevelC LevelC => levelC;

        /// <summary>
        /// Get report for level X
        /// </summary>
        /// <returns></returns>
        public virtual SignatureLevelX LevelX => levelX;

        /// <summary>
        /// Get report for level XL
        /// </summary>
        /// <returns></returns>
        public virtual SignatureLevelXL LevelXL => levelXL;

        /// <summary>
        /// Get report for level A
        /// </summary>
        /// <returns></returns>
        public virtual SignatureLevelA LevelA => levelA;
    }
}
