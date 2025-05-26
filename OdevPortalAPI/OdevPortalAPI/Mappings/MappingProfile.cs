using AutoMapper;
using OdevPortalAPI.DTOs;
using OdevPortalAPI.Models;

namespace OdevPortalAPI.Mappings
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            // Assignment Mappings
            CreateMap<Assignment, AssignmentDTO>()
                .ForMember(dest => dest.CourseName, opt => opt.MapFrom(src => src.Course != null ? src.Course.Name : null));

            CreateMap<AssignmentCreateDTO, Assignment>();

            CreateMap<AssignmentUpdateDTO, Assignment>();

            // Course Mappings
            CreateMap<Course, CourseDTO>()
                .ForMember(dest => dest.DepartmentName, opt => opt.MapFrom(src => src.Department != null ? src.Department.Name : null))
                .ForMember(dest => dest.TeacherName, opt => opt.MapFrom(src => src.Teacher != null ? $"{src.Teacher.FirstName} {src.Teacher.LastName}" : null));

            CreateMap<CourseCreateDTO, Course>();

            CreateMap<CourseUpdateDTO, Course>();

            // Department Mappings
            CreateMap<Department, DepartmentDTO>();

            CreateMap<DepartmentCreateDTO, Department>();

            CreateMap<DepartmentUpdateDTO, Department>();

            // Notification Mappings
            CreateMap<Notification, NotificationDTO>();

            CreateMap<NotificationCreateDTO, Notification>();

            CreateMap<NotificationUpdateDTO, Notification>();

            // Submission Mappings
            CreateMap<Submission, SubmissionDTO>()
                .ForMember(dest => dest.AssignmentTitle, opt => opt.MapFrom(src => src.Assignment != null ? src.Assignment.Title : null))
                .ForMember(dest => dest.StudentName, opt => opt.MapFrom(src => src.Student != null ? $"{src.Student.FirstName} {src.Student.LastName}" : null));

            CreateMap<SubmissionCreateDTO, Submission>();

            CreateMap<SubmissionUpdateDTO, Submission>();

            CreateMap<GradeSubmissionDTO, Submission>();

            // User Mappings
            CreateMap<AppUser, UserDTO>()
                .ForMember(dest => dest.Roles, opt => opt.Ignore()); // Roles will be set manually

            CreateMap<RegisterDTO, AppUser>();
        }
    }
}