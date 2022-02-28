using System.ComponentModel;

namespace CAdESLib
{
    public enum SignatureProfile
    {
        [Description("$Enum_Signature_Profiles_None")]
        None = 0,

        [Description("$Enum_Signature_Profiles_BES")]
        BES = 1,

        [Description("$Enum_Signature_Profiles_EPES")]
        EPES = 2,

        [Description("$Enum_Signature_Profiles_T")]
        T = 3,

        [Description("$Enum_Signature_Profiles_C")]
        C = 4,

        [Description("$Enum_Signature_Profiles_XL")]
        XL = 5,

        [Description("$Enum_Signature_Profiles_X_Type1")]
        XType1 = 6,

        [Description("$Enum_Signature_Profiles_X_Type2")]
        XType2 = 7,

        [Description("$Enum_Signature_Profiles_XL_Type1")]
        XLType1 = 8,

        [Description("$Enum_Signature_Profiles_XL_Type2")]
        XLType2 = 9,

        [Description("$Enum_Signature_Profiles_A")]
        A = 10,
    }
}
