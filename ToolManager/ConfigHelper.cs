namespace ToolManager
{
    public static class ConfigHelper
    {
        public static App GetApp(this IConfiguration configuration)
        {
            return configuration.GetSection("App").Get<App>() ?? throw new KeyNotFoundException("App not found.");
        }
    }
}
