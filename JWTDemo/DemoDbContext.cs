using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace JWTDemo
{
    public class DemoDbContext:IdentityDbContext<DemoUser>
    {
        public DemoDbContext(DbContextOptions<DemoDbContext> options) 
            : base(options)
        {

        }
    }
}
