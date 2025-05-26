namespace OdevPortalAPI.Models
{
    public class Assignment : BaseEntity
    {
        public string Title { get; set; }
        public string Description { get; set; }
        public DateTime DueDate { get; set; }
        public int TotalPoints { get; set; }
        public int CourseId { get; set; }
        public string? AttachmentUrl { get; set; }

        // Navigation properties
        public virtual Course Course { get; set; }
        public virtual ICollection<Submission> Submissions { get; set; }
    }
}