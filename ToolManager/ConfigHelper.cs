namespace ToolManager
{
    public static class ConfigHelper
    {
        public static App GetApp(this IConfiguration configuration)
        {
            return configuration.GetValue<App>("App") ?? throw new KeyNotFoundException("App not found.");
        }
    }
}
