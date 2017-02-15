using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace AngularJSAuthentication.API.Entities
{
    public class Test
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [MaxLength(50)]
        public string Subject { get; set; }
    }
}