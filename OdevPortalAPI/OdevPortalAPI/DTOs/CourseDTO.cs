namespace OdevPortalAPI.DTOs
{
    public class CourseDTO
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Code { get; set; }
        public string Description { get; set; }
        public string Semester { get; set; }
        public int Credits { get; set; }
        public int DepartmentId { get; set; }
        public string DepartmentName { get; set; }
        public string TeacherId { get; set; }
        public string TeacherName { get; set; }
    }

    public class CourseCreateDTO
    {
        public string Name { get; set; }
        public string Code { get; set; }
        public string Description { get; set; }
        public string Semester { get; set; }
        public int Credits { get; set; }
        public int DepartmentId { get; set; }
        public string TeacherId { get; set; }
    }

    public class CourseUpdateDTO
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Code { get; set; }
        public string Description { get; set; }
        public string Semester { get; set; }
        public int Credits { get; set; }
        public int DepartmentId { get; set; }
        public string TeacherId { get; set; }
    }
}