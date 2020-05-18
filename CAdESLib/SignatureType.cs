using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Text;

namespace CAdESLib
{
    public enum SignatureType
    {
        [Description("$Enum_SignatureTypes_None")]
        None = 0,
        [Description("$Enum_SignatureTypes_CAdES")]
        CAdES = 1,

    }
}
