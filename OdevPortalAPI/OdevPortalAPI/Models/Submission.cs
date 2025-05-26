namespace OdevPortalAPI.Models
{
    public class Submission : BaseEntity
    {
        public string SubmissionText { get; set; }
        public string? FileUrl { get; set; }
        public DateTime SubmissionDate { get; set; } = DateTime.Now;
        public int? Score { get; set; }
        public string? Feedback { get; set; }
        public bool IsGraded { get; set; } = false;
        public int AssignmentId { get; set; }
        public string StudentId { get; set; }

        // Navigation properties
        public virtual Assignment Assignment { get; set; }
        public virtual AppUser Student { get; set; }
    }
}