using NLog;
using System.Collections.Generic;
using System.Linq;

namespace CAdESLib.Helpers
{
    public class CAdESLogger : ICAdESLogger
    {
        private static readonly Logger nloglogger = LogManager.GetCurrentClassLogger();

        private List<ICAdESLoggerEntry> entries = new List<ICAdESLoggerEntry>();

        public void Clear()
        {
            entries = new List<ICAdESLoggerEntry>();
        }

        public void Error(string message)
        {
            var frame = (new System.Diagnostics.StackTrace()).GetFrame(1)?.GetMethod();
            nloglogger.Trace($"{frame?.DeclaringType?.ToString().Split(".").Last()}.{frame?.Name}: {message}");
            entries.Add(new CAdESLoggerEntry(LogLevel.Error, message));
        }

        public void Warn(string message)
        {
            var frame = (new System.Diagnostics.StackTrace()).GetFrame(1)?.GetMethod();
            nloglogger.Trace($"{frame?.DeclaringType?.ToString().Split(".").Last()}.{frame?.Name}: {message}");
            entries.Add(new CAdESLoggerEntry(LogLevel.Warn, message));
        }

        public IEnumerable<ICAdESLoggerEntry> GetEntries()
        {
            return entries.AsReadOnly();
        }

        public void Info(string message)
        {
            var frame = (new System.Diagnostics.StackTrace()).GetFrame(1)?.GetMethod();
            nloglogger.Trace($"{frame?.DeclaringType?.ToString().Split(".").Last()}.{frame?.Name}: {message}");
            entries.Add(new CAdESLoggerEntry(LogLevel.Info, message));
        }
        
        public void Trace(string message)
        {
            var frame = (new System.Diagnostics.StackTrace()).GetFrame(1)?.GetMethod();
            nloglogger.Trace($"{frame?.DeclaringType?.ToString().Split(".").Last()}.{frame?.Name}: {message}");
            entries.Add(new CAdESLoggerEntry(LogLevel.Trace, message));
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
