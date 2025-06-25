using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Concurrent;
using System.Collections.Frozen;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using Yarp.ReverseProxy.Transforms;
using Yarp.ReverseProxy.Transforms.Builder;

namespace ToolManager
{
    public class Program
    {
        private static readonly ConcurrentDictionary<string, DateTime> _states = new();

        public static async Task Main(string[] args)
        {
            var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions
            {
                Args = args,
                WebRootPath = ""
            });

            if (builder.Environment.IsDevelopment())
            {
                builder.WebHost.UseKestrelHttpsConfiguration();
            }

            builder.WebHost.ConfigureKestrel(serverOptions =>
            {
                serverOptions.Limits.MaxRequestBodySize = long.MaxValue;
            });

            builder.Services.ConfigureHttpJsonOptions(options =>
            {
                options.SerializerOptions.TypeInfoResolverChain.Insert(0, AppJsonSerializerContext.Default);
            });

            builder.Services.AddReverseProxy().LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

            builder.Services.AddAuthorizationBuilder()
            .AddPolicy("AuthenticatedOnly", policy =>
            {
                policy.RequireAuthenticatedUser();
            });

            builder.Services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie(options =>
            {
                options.Cookie.Name = "s_";
                options.Cookie.HttpOnly = true;
            })
            .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
            {
                options.Authority = $"https://login.microsoftonline.com/{builder.Configuration["EntraID:TenantId"]}/v2.0";
                options.ClientId = builder.Configuration["EntraID:ClientId"];
                options.ClientSecret = builder.Configuration["EntraID:ClientSecret"];
                options.ResponseType = "code";
                options.SaveTokens = true;
                options.Scope.Add("openid");
                options.Scope.Add("profile");
                options.Scope.Add("https://graph.microsoft.com/.default");

                if (builder.Environment.IsProduction())
                {
                    options.Events = new OpenIdConnectEvents
                    {
                        OnRedirectToIdentityProvider = context =>
                        {
                            var request = context.Request;
                            var host = request.Host.Value;
                            var pathBase = request.PathBase.Value;
                            var callbackPath = context.Options.CallbackPath.Value;
                            var redirectUri = $"https://{host}{pathBase}{callbackPath}";

                            context.ProtocolMessage.RedirectUri = redirectUri;

                            return Task.CompletedTask;
                        }
                    };
                }
            });

            builder.Services.AddSingleton<ITransformProvider, DynamicDestinationTransformProvider>();

            var app = builder.Build();

            // Admin Consent flow initiator
            app.MapGet("/admin-consent", () =>
            {
                var clientId = builder.Configuration["EntraID:ClientId"];
                var scopes = Uri.EscapeDataString("openid profile https://graph.microsoft.com/.default");

                var state = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
                _states[state] = DateTime.UtcNow;

                var url = $"https://login.microsoftonline.com/{builder.Configuration["EntraID:TenantId"]}/v2.0/adminconsent" +
                          $"?client_id={clientId}" +
                          $"&scope={scopes}" +
                          $"&redirect_uri={builder.Configuration["EntraID:RedirectUri"]}" +
                          $"&state={state}";

                return Results.Redirect(url);
            });

            // Callback handler
            app.MapGet("/admin-consent/callback", (
                [FromQuery] string? state,
                [FromQuery] string? admin_consent,
                [FromQuery] string? tenant,
                [FromQuery] string? scope,
                [FromQuery] string? error,
                [FromQuery] string? error_description) =>
            {
                if (!_states.TryRemove(state ?? "", out _))
                {
                    return Results.Text("❌ Invalid or missing state parameter.");
                }

                if (admin_consent == "True")
                {
                    return Results.Text($"✅ Consent granted for tenant {tenant} scope={scope}");
                }

                return Results.Text($"❌ Consent failed: {error} - {error_description}");
            });

            app.MapGet("/logout", async (HttpContext context) =>
            {
                // Sign out of the local cookie authentication
                await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

                // Sign out of the OpenID Connect session and redirect to Entra ID logout
                var callbackUrl = Uri.EscapeDataString("https://localhost:5000/"); // Change to your post-logout redirect URI
                var tenantId = builder.Configuration["EntraID:TenantId"];
                var logoutUrl = $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/logout?post_logout_redirect_uri={callbackUrl}";

                await context.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme, new AuthenticationProperties
                {
                    RedirectUri = logoutUrl
                });
            });

            app.MapGet("/apps", async (HttpContext http, IConfiguration config) =>
            {
                var apps = config.GetApps();

                await http.Response.WriteAsync(
                    $"""
                    <html>              
                        <head>
                            <meta name="color-scheme" content="only dark" />
                        </head>
                        <body>
                            <h1>Select an App</h1>
                            <form method="post" action="/apps">
                                {string.Join("\n", apps.Select(app => $"""
                                <button type="submit" name="appName" value="{app.Name}">{app.Name}</button>
                                """))}
                            </form>
                        </body>
                    </html>
                    """);
            }).RequireAuthorization();

            app.MapPost("/apps", (HttpContext context, [FromServices] IConfiguration config, [FromForm] string appName) =>
            {
                context.Response.Cookies.Append("app", appName, new CookieOptions
                {
                    SameSite = SameSiteMode.Lax,
                    HttpOnly = true
                });

                context.Response.Redirect("/apps");
            }).RequireAuthorization().DisableAntiforgery();

            app.MapReverseProxy(proxyPipeline =>
            {
            });

            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();

            app.Run();

        }
    }

    public record App(string Name, int Instance, int Port);
    public record Instance(int Name, string Domain);

    [JsonSerializable(typeof(App))]
    [JsonSerializable(typeof(Instance))]
    internal partial class AppJsonSerializerContext : JsonSerializerContext
    {

    }

    public class DynamicDestinationTransformProvider : ITransformProvider
    {
        public void Apply(TransformBuilderContext context)
        {
            context.RequestTransforms.Add(new DynamicDestinationTransform(context.Services));
        }

        public void ValidateCluster(TransformClusterValidationContext context)
        {

        }

        public void ValidateRoute(TransformRouteValidationContext context)
        {

        }

        private sealed class DynamicDestinationTransform : RequestTransform
        {
            private readonly FrozenSet<App> _apps;
            private readonly Instance _instance;
            private readonly FrozenSet<Instance> _instances;
            private readonly ILogger<DynamicDestinationTransform> _logger;

            public DynamicDestinationTransform(IServiceProvider services)
            {
                var config = services.GetRequiredService<IConfiguration>();
                _apps = config.GetApps();
                _instance = config.GetInstance();
                _instances = config.GetInstances();
                _logger = services.GetRequiredService<ILogger<DynamicDestinationTransform>>();
            }

            public override async ValueTask ApplyAsync(RequestTransformContext context)
            {
                if (!context.HttpContext.Request.Cookies.TryGetValue("app", out var selectedApp))
                {
                    return;
                }

                Log.LogSelectedApp(_logger, selectedApp);

                if (_apps.FirstOrDefault(x => string.Equals(x.Name, selectedApp, StringComparison.Ordinal)) is not { } app)
                {
                    return;
                }

                Log.LogFoundSelectedApp(_logger, app);

                Log.LogInstance(_logger, _instance.Name, app.Instance);

                Uri newUri;
                if (_instance.Name != app.Instance && _instances.TryGetInstance(app.Instance, out var instance))
                {
                    newUri = new UriBuilder("https", instance.Domain, 443, context.HttpContext.Request.Path).Uri;
                }
                else
                {
                    newUri = new UriBuilder("http", app.Name, app.Port, context.HttpContext.Request.Path).Uri;
                }

                Log.LogProxyUri(_logger, newUri);

                Rewrite(context, newUri);

                await ValueTask.CompletedTask;
            }
        }

        private static void Rewrite(RequestTransformContext context, Uri uri)
        {
            if (context.ProxyRequest.Headers.TryGetValues("Cookie", out var cookieHeaders))
            {
                var filteredCookies = cookieHeaders
                    .SelectMany(header => header.Split(';', StringSplitOptions.RemoveEmptyEntries))
                    .Select(cookie => cookie.Trim())
                    .Where(cookie =>
                    {
                        var cookieName = cookie.Split('=', 2)[0].Trim();
                        return !cookieName.StartsWith("s_", StringComparison.OrdinalIgnoreCase);
                    });

                var newCookieHeader = string.Join("; ", filteredCookies);
                context.ProxyRequest.Headers.Remove("Cookie");
                if (!string.IsNullOrEmpty(newCookieHeader))
                {
                    context.ProxyRequest.Headers.Add("Cookie", newCookieHeader);
                }
            }

            context.ProxyRequest.RequestUri = uri;
            context.ProxyRequest.Headers.Host = uri.Authority;
        }
    }
}