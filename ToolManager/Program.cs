using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Frozen;
using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using System.Text.Json.Serialization;
using Yarp.ReverseProxy.Transforms;
using Yarp.ReverseProxy.Transforms.Builder;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace ToolManager
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions
            {
                Args = args,
                WebRootPath = ""
            });

            var isPrimary = false;
            if (builder.Environment.IsProduction() && Environment.GetEnvironmentVariable("ISPRIMARY") is not null)
            {
                isPrimary = true;
            }
            else
            {
                isPrimary = !args.Any(x => x.Contains("--urls"));
                if (isPrimary)
                {
                    //using var process = Process.Start(new ProcessStartInfo
                    //{
                    //    FileName = Environment.ProcessPath,
                    //    Arguments = "--urls=http://localhost:5001/"
                    //});
                }
            }

            var instance = builder.Configuration.GetInstance();
            var instance0 = builder.Configuration.GetInstances().GetInstance0();

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

            Action<CookieAuthenticationOptions> configureCookieOptions = options =>
            {
                options.Cookie.Name = "session";
                options.Cookie.Domain = builder.Environment.IsDevelopment() ? null : builder.Configuration["Authentication:CookieDomain"];
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.Cookie.HttpOnly = true;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                options.ExpireTimeSpan = TimeSpan.FromHours(1);
            };


            if (instance.Name == 0)
            {
                builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                    .AddCookie(options =>
                    {
                        configureCookieOptions(options);
                        options.LoginPath = "/login";
                    });
            }
            else
            {
                builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                   .AddCookie(options =>
                   {
                       configureCookieOptions(options);
                       options.Events.OnRedirectToLogin = (context) =>
                       {
                           var location = $"https://{instance0.Domain}";

                           Log.LogOnRedirectToLogin(context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>(), location);
                           
                           context.Response.Redirect(location);

                           return Task.CompletedTask;
                       };
                   });
            }

            if (instance.Name == 0)
            {
                builder.Services
                    .AddOpenIddict()
                    .AddCore(options =>
                    {
                    })
                    .AddServer(options =>
                    {
                        //options.AddDevelopmentEncryptionCertificate();
                        //options.AddDevelopmentSigningCertificate();

                        // Expose the standard endpoints
                        options.SetAuthorizationEndpointUris("/connect/authorize")
                               .SetTokenEndpointUris("/connect/token");

                        // We’ll do Auth‑Code + PKCE
                        options.AllowAuthorizationCodeFlow()
                               .RequireProofKeyForCodeExchange();

                        // Standard scopes
                        options.RegisterScopes(Scopes.OpenId, Scopes.Profile, "api");

                        // Ephemeral keys (rotate on restart)
                        options.AddEphemeralEncryptionKey()
                               .AddEphemeralSigningKey();

                        // Tell OpenIddict to use ASP‑NET Core plumbing:
                        options.UseAspNetCore()
                               .EnableAuthorizationEndpointPassthrough()
                               .EnableTokenEndpointPassthrough();
                    })
                    .AddValidation(options =>
                    {
                        // So our APIs can easily validate tokens
                        //options.UseLocalServer();
                        //options.UseAspNetCore();
                    });
            }

            builder.Services.AddSingleton<ITransformProvider, DynamicDestinationTransformProvider>();

            var app = builder.Build();

            if (instance.Name == 0)
            {
                app.MapGet("/login", async (HttpContext context, [FromQuery] string? returnUrl) =>
                {
                    await context.Response.WriteAsync(
    $"""
<html>
    <head>
        <meta name="color-scheme" content="only dark" />
    </head>
    <body>                
        <form method="post" action="/login?returnUrl={returnUrl}">
            <input name="username" placeholder="Username"/><br/>
            <input name="password" type="password" placeholder="Password"/><br/>
            <button>Log in</button>
        </form>
    </body>
</html>
""");
                });

                app.MapPost("/login", async (
                    HttpContext context,
                    [FromServices] IConfiguration config,
                    [FromForm] string username,
                    [FromForm] string password,
                    [FromQuery] string? returnUrl) =>
                {
                    var creds = config.GetCredentials();
                    // simple lookup in our env‑var list
                    if (!creds.Any(u => u.Username == username && u.Password == password))
                    {
                        context.Response.StatusCode = 401;
                        await context.Response.WriteAsync("Invalid credentials");
                        return;
                    }

                    // create a cookie‑based identity
                    var claims = new[]
                    {
                    new Claim(Claims.Subject, username),
                    new Claim(Claims.Name, username)
                    };
                    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                    var principal = new ClaimsPrincipal(identity);
                    await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

                    if (string.IsNullOrWhiteSpace(returnUrl))
                    {
                        returnUrl = "/apps";
                    }

                    context.Response.Redirect(returnUrl);
                }).DisableAntiforgery();
            }

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
                    Domain = builder.Environment.IsDevelopment() ? null : builder.Configuration["Authentication:CookieDomain"],
                    SameSite = SameSiteMode.Lax,
                    Secure = true
                });

                context.Response.Redirect("/apps");
            }).RequireAuthorization().DisableAntiforgery();

            app.MapGet("/bablablablablablablablab", (HttpContext context) =>
            {
            }).DisableAntiforgery();

            app.MapReverseProxy(proxyPipeline =>
            {
            });

            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();

            app.Run();

        }
    }

    public record Credential(string Username, string Password);
    public record App(string Name, int Instance, int Port);
    public record Instance(int Name, string Domain);

    [JsonSerializable(typeof(Credential))]
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
            context.ProxyRequest.RequestUri = uri;
            context.ProxyRequest.Headers.Host = uri.Authority;
        }
    }
}
