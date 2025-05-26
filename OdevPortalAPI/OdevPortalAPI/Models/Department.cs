namespace OdevPortalAPI.Models
{
    public class Department : BaseEntity
    {
        public string Name { get; set; }
        public string Description { get; set; }

        // Navigation property
        public virtual ICollection<Course> Courses { get; set; }
    }
}