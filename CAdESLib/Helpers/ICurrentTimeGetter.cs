using System;

namespace CAdESLib.Helpers
{
    public interface ICurrentTimeGetter
    {
        DateTime CurrentUtcTime { get; }
    }

    public class CurrentTimeGetter : ICurrentTimeGetter
    {
        public DateTime CurrentUtcTime { get { return DateTime.UtcNow; } }
    }
}
