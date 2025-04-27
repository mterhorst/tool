namespace ToolManager
{
    public static partial class Log
    {
        [LoggerMessage(2001, LogLevel.Information, "Selected app: {selected}.")]
        public static partial void LogSelectedApp(ILogger logger, string selected);

        [LoggerMessage(2002, LogLevel.Information, "Found selected app: {app}.")]
        public static partial void LogFoundSelectedApp(ILogger logger, App app);

        [LoggerMessage(2003, LogLevel.Information, "Proxy uri: {uri}.")]
        public static partial void LogProxyUri(ILogger logger, Uri uri);
    }
}
