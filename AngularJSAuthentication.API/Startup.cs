using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

using Microsoft.Owin;
using Microsoft.Owin;
using Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Http;

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
            // The “HttpConfiguration” object is used to configure API routes, so we’ll pass this object to method “Register” in “WebApiConfig” class.
            HttpConfiguration config = new HttpConfiguration();
            //Lastly, we’ll pass the “config” object to the extension method “UseWebApi” which will be responsible to wire up ASP.NET Web API to our Owin server pipeline.
            WebApiConfig.Register(config);
            app.UseWebApi(config);
        }

    }
}