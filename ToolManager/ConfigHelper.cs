using System.Collections.Frozen;

namespace ToolManager
{
    public static class ConfigHelper
    {
        public static FrozenSet<Credential> GetCredentials(this IConfiguration configuration)
        {
            return configuration.GetSection("Users").Get<IList<Credential>>()!.ToFrozenSet();
        }

        public static FrozenSet<App> GetApps(this IConfiguration configuration)
        {
            return configuration.GetSection("Apps").Get<IList<App>>()!.ToFrozenSet();
        }

    }
}
