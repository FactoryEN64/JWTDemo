using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTDemo.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly SignInManager<DemoUser> _signInManager;
        private readonly UserManager<DemoUser> _userManager;
        private readonly IConfiguration _config;
        public AccountController(
            UserManager<DemoUser> userManager,
            SignInManager<DemoUser> signInManager,
            IConfiguration config)
        {
            _config = config;
            _signInManager = signInManager;
            _userManager = userManager;
        }
        [AllowAnonymous]
        [HttpPost]
        public async Task<ActionResult<UserRegisterResponse>> Register([FromBody] UserRegisterRequest input)
        {
            var user = new DemoUser { UserName = input.UserName, Email = input.Email };
            var result = await _userManager.CreateAsync(user, input.Password);
            if (result.Succeeded)
            {
                return new UserRegisterResponse { UserName = input.UserName, Result = "Success" };
            }
            else
            {
                return new UserRegisterResponse { UserName = input.UserName, Result = "Falied" };
            }
        }
        [AllowAnonymous]
        [HttpPost]
        public async Task<ActionResult<UserLoginResponse>> Login([FromBody] UserLoginRequest user)
        {
            var result = await _signInManager.PasswordSignInAsync(user.UserName, user.Password, true, true);
            if (result.Succeeded)
            {
                string jwtToken = CreateToken(user.UserName, "admin");
                return new UserLoginResponse
                {
                    UserName = user.UserName,
                    JWTToken = jwtToken,
                };
            }
            else
            {
                return new UserLoginResponse { UserName = user.UserName };
            }
        }

        [Authorize]
        [HttpGet]
        public ActionResult<string> GetTest()
        {
            var identity = (System.Security.Claims.ClaimsIdentity)this.Request.HttpContext.User.Identity;
            StringBuilder sb = new StringBuilder();
            foreach (var item in identity.Claims)
            {
                sb.Append(item.Type + ":" + item.Value + "\r\n");
            }
            sb.Append("userName:" + HttpContext.User.Identity.Name + "\r\n");
            sb.Append("isAdmin:" + HttpContext.User.IsInRole("admin"));
            return sb.ToString();
        }

        private string CreateToken(string userName, string role)
        {
            var claims = new[] {
                new Claim(ClaimTypes.Name,userName),
                new Claim(ClaimTypes.Role,role),
                new Claim(JwtRegisteredClaimNames.Iat,DateTimeOffset.Now.ToUnixTimeSeconds().ToString(),ClaimValueTypes.Integer64),
                new Claim(JwtRegisteredClaimNames.AuthTime,DateTimeOffset.Now.ToUnixTimeSeconds().ToString(),ClaimValueTypes.Integer64)
            };

            var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:SecretKey"]));

            var algorithm = SecurityAlgorithms.HmacSha256;

            var signingCredentials = new SigningCredentials(secretKey, algorithm);

            var jwtSecurityToken = new JwtSecurityToken(
                _config["Jwt:Issuer"],
                _config["Jwt:Audience"],
                claims,
                DateTime.Now,
                DateTime.Now.AddSeconds(30),
                signingCredentials
                );

            var token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            return token;
        }
    }
}
