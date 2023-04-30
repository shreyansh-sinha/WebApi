using System.Text;

namespace WebApi
{
    public class BasicAuthHandler
    {
        private readonly RequestDelegate next;
        public BasicAuthHandler(RequestDelegate next)
        {
            this.next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            if(!context.Request.Headers.ContainsKey("Authorization"))
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("UnAuthorized");
                return;
            }

            // Basic username:password
            var header = context.Request.Headers["Authorization"].ToString();
            var encodedCreds = header.Substring(6);
            var decodedCreds = Encoding.UTF8.GetString(Convert.FromBase64String(encodedCreds));
            string[] uidPwd = decodedCreds.Split(':');
            string uid = uidPwd[0];
            string pwd = uidPwd[1];

            if(uid != "john" || pwd != "password")
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("UnAuthorized");
                return;
            }

            Console.WriteLine("Authorization Successful");
            next(context);
        }
    }
}
