using Box.V2;
using Box.V2.Auth;
using Box.V2.Config;
using BoxDevEditionAuthHelper;
using Nito.AsyncEx;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

/*Install the follow Nuget packages:
 * 
 * Box Windows SDK V2
 * 
 * Also, add a reference to System.Configuration
 */

namespace BoxDevEditionClient
{
    class Program
    {
        static readonly string CLIENT_ID = ConfigurationManager.AppSettings["boxClientId"];
        static readonly string CLIENT_SECRET = ConfigurationManager.AppSettings["boxClientSecret"];
        static readonly string ENTERPRISE_ID = ConfigurationManager.AppSettings["boxEnterpriseId"];
        static readonly string JWT_PRIVATE_KEY_PASSWORD = ConfigurationManager.AppSettings["boxPrivateKeyPassword"];
        static readonly string JWT_PRIVATE_KEY = ConfigurationManager.AppSettings["boxPrivateKey"];
        static readonly string REFRESH_TOKEN = "NOT_NEEDED_BUT_MUST_BE_PRESENT";

        static readonly BoxJWTHelper boxJWTHelper = new BoxJWTHelper(ENTERPRISE_ID, CLIENT_ID, CLIENT_SECRET, JWT_PRIVATE_KEY, JWT_PRIVATE_KEY_PASSWORD);
        static BoxClient adminClient;
        static BoxClient userClient;

        static void Main(string[] args)
        {
            //http://blog.stephencleary.com/2012/02/async-console-programs.html
            try
            {
                AsyncContext.Run(() => MainAsync());
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex);
            }

            Console.WriteLine();
            Console.Write("Press return to exit...");
            Console.ReadLine();
        }


        static async Task MainAsync()
        {
            var enterpriseToken = boxJWTHelper.GetEnterpriseToken();
            var config = new BoxConfig(CLIENT_ID, CLIENT_SECRET, new Uri("http://localhost"));
            var adminSession = new OAuthSession(enterpriseToken, REFRESH_TOKEN, 3600, "bearer");
            adminClient = new BoxClient(config, adminSession);

            string appUserId = boxJWTHelper.CreateAppUser("test user", enterpriseToken);
            var userToken = boxJWTHelper.GetUserToken(appUserId);
            var userSession = new OAuthSession(userToken, REFRESH_TOKEN, 3600, "bearer");
            userClient = new BoxClient(config, userSession);

            var items = await adminClient.FoldersManager.GetFolderItemsAsync("0", 100);
            Console.WriteLine("Admin account root folder items:");
            items.Entries.ForEach((i) => Console.WriteLine("\t{0}", i.Name));

            var userDetails = await userClient.UsersManager.GetCurrentUserInformationAsync();
            Console.WriteLine("\nApp User Details:");
            Console.WriteLine("\tId: {0}", userDetails.Id);
            Console.WriteLine("\tName: {0}", userDetails.Name);
            Console.WriteLine("\tStatus: {0}", userDetails.Status);

            boxJWTHelper.DeleteAppUser(appUserId, enterpriseToken);
        }

    }
}

