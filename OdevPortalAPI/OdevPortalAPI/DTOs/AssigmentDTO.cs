namespace OdevPortalAPI.DTOs
{
    public class AssignmentDTO
    {
        public int Id { get; set; }
        public string Title { get; set; }
        public string Description { get; set; }
        public DateTime DueDate { get; set; }
        public int TotalPoints { get; set; }
        public int CourseId { get; set; }
        public string CourseName { get; set; }
        public string? AttachmentUrl { get; set; }
    }

    public class AssignmentCreateDTO
    {
        public string Title { get; set; }
        public string Description { get; set; }
        public DateTime DueDate { get; set; }
        public int TotalPoints { get; set; }
        public int CourseId { get; set; }
        public string? AttachmentUrl { get; set; }
    }

    public class AssignmentUpdateDTO
    {
        public int Id { get; set; }
        public string Title { get; set; }
        public string Description { get; set; }
        public DateTime DueDate { get; set; }
        public int TotalPoints { get; set; }
        public string? AttachmentUrl { get; set; }
    }
}