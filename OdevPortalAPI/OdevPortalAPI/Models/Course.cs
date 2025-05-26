namespace OdevPortalAPI.Models
{
    public class Course : BaseEntity
    {
        public string Name { get; set; }
        public string Code { get; set; }
        public string Description { get; set; }
        public string Semester { get; set; }
        public int Credits { get; set; }
        public int DepartmentId { get; set; }
        public string TeacherId { get; set; }

        // Navigation properties
        public virtual Department Department { get; set; }
        public virtual AppUser Teacher { get; set; }
        public virtual ICollection<Assignment> Assignments { get; set; }
        public virtual ICollection<StudentCourse> EnrolledStudents { get; set; }
    }
}