using System;
using Microsoft.Owin;
using Owin;
using System.Web.Http;
using AngularJSAuthentication.API.Providers;
using Microsoft.Owin.Security.OAuth;

[assembly: OwinStartup(typeof(AngularJSAuthentication.API.Startup))]
namespace AngularJSAuthentication.API
{
    /// <summary>
    /// This class will be fired once our server starts
    /// Notice the “assembly” attribute which states which class to fire on start-up 
    /// </summary>
    public class Startup
    {
        /// <summary>
        /// The “Configuration” method accepts parameter of type “IAppBuilder” this parameter will be supplied by the host at run-time. 
        /// </summary>
        /// <param name="app">
        /// This “app” parameter is an interface which will be used to compose the application for our Owin server.
        /// </param>
        public void Configuration(IAppBuilder app)
        {
            ConfigureOAuth(app);

            // The “HttpConfiguration” object is used to configure API routes, so we’ll pass this object to method “Register” in “WebApiConfig” class.
            HttpConfiguration config = new HttpConfiguration();
            
            // Lastly, we’ll pass the “config” object to the extension method “UseWebApi” which will be responsible to wire up ASP.NET Web API to our Owin server pipeline.
            WebApiConfig.Register(config);

            // Allow CORS for ASP.NET Web API
            app.UseCors(Microsoft.Owin.Cors.CorsOptions.AllowAll);

            app.UseWebApi(config);
        }

        public void ConfigureOAuth(IAppBuilder app)
        {
            OAuthAuthorizationServerOptions OAuthServerOptions = new OAuthAuthorizationServerOptions()
            {
                AllowInsecureHttp = true,
                
                // The path for generating tokens will be as :”http://localhost:port/token”. We’ll see how we will issue HTTP POST request to generate token in the next steps.
                TokenEndpointPath = new PathString("/token"),
                
                // We’ve specified the expiry for token to be 24 hours, so if the user tried to use the same token for authentication after 24 hours from the issue time, his request will be rejected and HTTP status code 401 is returned.
                AccessTokenExpireTimeSpan = TimeSpan.FromHours(1), // Test on 1 minute

                // We’ve specified the implementation on how to validate the credentials for users asking for tokens in custom class named “SimpleAuthorizationServerProvider”.
                Provider = new SimpleAuthorizationServerProvider()
            };

            // Token Generation
            app.UseOAuthAuthorizationServer(OAuthServerOptions);
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions());
        }

    }
}