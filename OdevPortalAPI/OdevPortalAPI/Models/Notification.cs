namespace OdevPortalAPI.Models
{
    public class Notification : BaseEntity
    {
        public string Title { get; set; }
        public string Message { get; set; }
        public bool IsRead { get; set; } = false;
        public string UserId { get; set; }
        public string NotificationType { get; set; } // "Assignment", "Submission", "Grade"

        // Navigation property
        public virtual AppUser User { get; set; }
    }
}