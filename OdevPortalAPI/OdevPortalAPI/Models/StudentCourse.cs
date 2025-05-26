using System;

namespace OdevPortalAPI.Models
{
    public class StudentCourse : BaseEntity
    {
        public string StudentId { get; set; }
        public int CourseId { get; set; }
        public DateTime EnrollmentDate { get; set; } = DateTime.Now;

        // Navigation properties
        public virtual AppUser Student { get; set; }
        public virtual Course Course { get; set; }
    }
}