using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;

namespace Role_Menu_MVC.Controllers
{
    public class HomeController : Controller
    {
        [AllowAnonymous]
        public ActionResult Index()
        {
            return View();
        }

        [Authorize]
        public ActionResult Profile()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        public ActionResult Index(User user)
        {
            UsersEntities usersEntities = new UsersEntities();
            RoleUser roleUser = usersEntities.ValidateUser(user.Username, user.Password).FirstOrDefault();

            string message = string.Empty;
            switch (roleUser.UserId.Value)
            {
                case -1:
                    message = "Username and/or password is incorrect.";
                    break;
                case -2:
                    message = "Account has not been activated.";
                    break;
                default:
                    FormsAuthenticationTicket ticket = new FormsAuthenticationTicket(1, user.Username, DateTime.Now, DateTime.Now.AddMinutes(2880), user.RememberMe, roleUser.Roles, FormsAuthentication.FormsCookiePath);
                    string hash = FormsAuthentication.Encrypt(ticket);
                    HttpCookie cookie = new HttpCookie(FormsAuthentication.FormsCookieName, hash);

                    if (ticket.IsPersistent)
                    {
                        cookie.Expires = ticket.Expiration;
                    }
                    Response.Cookies.Add(cookie);
                    if (!string.IsNullOrEmpty(Request.Form["ReturnUrl"]))
                    {
                        return RedirectToAction(Request.Form["ReturnUrl"].Split('/')[2]);
                    }
                    else
                    {
                        return RedirectToAction("Profile");
                    }
            }

            ViewBag.Message = message;
            return View(user);
        }

        [Authorize(Roles="Administrator")]
        public ActionResult UserDetails()
        {
            UsersEntities usersEntities = new UsersEntities();  
            List<User> users = usersEntities.Users.ToList();
            return View(users);
        }

        //[HttpPost]
        //[Authorize]
        public ActionResult Logout()
        {
            FormsAuthentication.SignOut();
            return RedirectToAction("Index");
        }
    }
}