﻿//using AngularJSAuthentication.API.Entities;
using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Web;
using AngularJSAuthentication.API.Entities;

namespace AngularJSAuthentication.API
{
    public class AuthContext : IdentityDbContext<IdentityUser>
    {
        public AuthContext()
            : base("AuthContext")
        {

        }

        public DbSet<Client> Clients { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }

        public DbSet<Test> ToanTest { get; set; }
    }

    public class MachineInfor
    {
        private string machineName = Environment.MachineName;

        public string ConnStr
        {
            get
            {
                //if (this.machineName.Contains("TOANLE"))
                    return string.Empty;
            }
        }
    }

}