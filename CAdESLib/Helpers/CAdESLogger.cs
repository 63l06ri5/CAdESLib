using System.Collections.Generic;

namespace CAdESLib.Helpers
{
    public class CAdESLogger : ICAdESLogger
    {
        private List<ICAdESLoggerEntry> entries = new List<ICAdESLoggerEntry>();

        public void Clear()
        {
            entries = new List<ICAdESLoggerEntry>();
        }

        public void Error(string message)
        {
            entries.Add(new CAdESLoggerEntry(LogLevel.Error, message));
        }

        public void Warn(string message)
        {
            entries.Add(new CAdESLoggerEntry(LogLevel.Warn, message));
        }

        public IEnumerable<ICAdESLoggerEntry> GetEntries()
        {
            return entries.AsReadOnly();
        }

        public void Info(string message)
        {
            entries.Add(new CAdESLoggerEntry(LogLevel.Info, message));
        }
    }

    public class CAdESLoggerEntry : ICAdESLoggerEntry
    {
        public CAdESLoggerEntry(LogLevel logLevel, string message)
        {
            LogLevel = logLevel;
            Message = message;
        }
        public LogLevel LogLevel { get; private set; }

        public string Message { get; private set; }
    }
}
