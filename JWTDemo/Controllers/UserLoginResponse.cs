namespace JWTDemo.Controllers
{
    public class UserLoginResponse
    {
        public string UserName { get; set; }
        public string JWTToken { get; set; }
    }
}