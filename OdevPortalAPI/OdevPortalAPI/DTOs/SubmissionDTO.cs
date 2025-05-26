namespace OdevPortalAPI.DTOs
{
    public class SubmissionDTO
    {
        public int Id { get; set; }
        public string SubmissionText { get; set; }
        public string? FileUrl { get; set; }
        public DateTime SubmissionDate { get; set; }
        public int? Score { get; set; }
        public string? Feedback { get; set; }
        public bool IsGraded { get; set; }
        public int AssignmentId { get; set; }
        public string AssignmentTitle { get; set; }
        public string StudentId { get; set; }
        public string StudentName { get; set; }
    }

    public class SubmissionCreateDTO
    {
        public string SubmissionText { get; set; }
        public string? FileUrl { get; set; }
        public int AssignmentId { get; set; }
    }

    public class SubmissionUpdateDTO
    {
        public int Id { get; set; }
        public string SubmissionText { get; set; }
        public string? FileUrl { get; set; }
    }

    public class GradeSubmissionDTO
    {
        public int Id { get; set; }
        public int Score { get; set; }
        public string Feedback { get; set; }
    }
}