using Microsoft.AspNetCore.Identity;

namespace OdevPortalAPI.Models
{
    public class AppUser : IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string? Address { get; set; }
        public string? City { get; set; }
        public string? Country { get; set; }
        public int? StudentNumber { get; set; }
        public string? Faculty { get; set; }
        public DateTime CreatedDate { get; set; } = DateTime.Now;
        public DateTime? ModifiedDate { get; set; }
        public bool IsActive { get; set; } = true;

        // Navigation properties
        public virtual ICollection<Submission> Submissions { get; set; }
        public virtual ICollection<Course> TaughtCourses { get; set; }
        public virtual ICollection<StudentCourse> EnrolledCourses { get; set; }
        public virtual ICollection<Notification> Notifications { get; set; }
    }
}