using System;
using System.Collections.Generic;
using System.Text;

namespace CAdESLib.Helpers
{
    public interface  ICAdESLogger
    {
        void Info(string message);
        void Error(string message);
        void Warn(string message);
        IEnumerable<ICAdESLoggerEntry> GetEntries();
        void Clear();
    }

    public interface ICAdESLoggerEntry
    {
        LogLevel LogLevel { get; }
        string Message { get; }
    }

    public enum LogLevel
    {
        Info = 1,
        Error = 2,
        Warn = 3
    }
}
