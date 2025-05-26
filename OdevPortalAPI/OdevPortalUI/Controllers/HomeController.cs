using Microsoft.AspNetCore.Mvc;

namespace OdevPortalAPI.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index() => View();
        public IActionResult Assignments() => View();
        public IActionResult AssignmentDetail() => View();
        public IActionResult StudentAssignments() => View();
        public IActionResult TeacherAssignments() => View();
        public IActionResult Courses() => View();
        public IActionResult CourseDetail() => View();
        public IActionResult StudentCourses() => View();
        public IActionResult TeacherCourses() => View();
        public IActionResult CoursesByDepartment() => View();
        public IActionResult Departments() => View();
        public IActionResult Notifications() => View();
        public IActionResult Submissions() => View();
        public IActionResult SubmissionDetail() => View();
        public IActionResult Users() => View();
        public IActionResult Profile() => View();
        public IActionResult Privacy() => View();
    }
}