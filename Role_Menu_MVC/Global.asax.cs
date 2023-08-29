using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Web;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;
using System.Web.Security;

namespace Role_Menu_MVC
{
    public class MvcApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);
        }

        protected void Application_AuthenticateRequest(Object sender, EventArgs e)
        {
            if (HttpContext.Current.User != null) //Admin & admin@123
            {
                if (HttpContext.Current.User.Identity.IsAuthenticated) //Admin & admin@123
                {
                    if (HttpContext.Current.User.Identity is FormsIdentity) //True
                    {
                        FormsIdentity id = (FormsIdentity)HttpContext.Current.User.Identity;
                        FormsAuthenticationTicket ticket = id.Ticket; //Gets the ticket created
                        string userData = ticket.UserData; // Ticket for the user logged in
                        string[] roles = userData.Split(','); //Checks which all Roles can access the Action Method
                        //true if the current GenericPrincipal is a member of the specified role; otherwise, false.
                        HttpContext.Current.User = new GenericPrincipal(id, roles);//Determines whether the current GenericPrincipal belongs to the specified role.
                    }
                }
            }
        }
    }
}
