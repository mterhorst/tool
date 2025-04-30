using System.Collections.Frozen;
using System.Diagnostics.CodeAnalysis;

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
        public static Instance GetInstance(this IConfiguration configuration)
        {
            return configuration.GetInstances().First(x => x.Name == configuration.GetSection("Instance").Get<int>());
        }

        public static FrozenSet<Instance> GetInstances(this IConfiguration configuration)
        {
            return configuration.GetSection("Instances").Get<IList<Instance>>()!.ToFrozenSet();
        }
    }

    public static class InstanceHelper
    {
        public static Instance GetInstance0(this FrozenSet<Instance> instances) => instances.First(x => x.Name == 0);

        public static bool TryGetInstance(this FrozenSet<Instance> instances, int name, [NotNullWhen(true)] out Instance? instance)
        {
            instance = instances.FirstOrDefault(x => x.Name == name);
            return instance is not null;
        }

    }
}
