using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace JWTDemo
{
    public class DemoUser : IdentityUser
    {
        [StringLength(128)]
        public string? DemoField { get; set; }
    }
}
