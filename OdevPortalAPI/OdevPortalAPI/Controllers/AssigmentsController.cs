using OdevPortalAPI.DTOs;
using OdevPortalAPI.Models;
using OdevPortalAPI.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using AutoMapper;

namespace OdevPortalAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class AssignmentsController : ControllerBase
    {
        private readonly AssignmentRepository _assignmentRepository;
        private readonly CourseRepository _courseRepository;
        private readonly NotificationRepository _notificationRepository;
        private readonly AppDbContext _context;
        private readonly IMapper _mapper;

        public AssignmentsController(
            AssignmentRepository assignmentRepository,
            CourseRepository courseRepository,
            NotificationRepository notificationRepository,
            AppDbContext context,
            IMapper mapper)
        {
            _assignmentRepository = assignmentRepository;
            _courseRepository = courseRepository;
            _notificationRepository = notificationRepository;
            _context = context;
            _mapper = mapper;
        }

        [HttpGet]
        public async Task<IActionResult> GetAll()
        {
            var assignments = await _assignmentRepository.GetAllWithDetailsAsync();
            var assignmentDtos = _mapper.Map<IEnumerable<AssignmentDTO>>(assignments);
            return Ok(assignmentDtos);
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> GetById(int id)
        {
            var assignment = await _assignmentRepository.GetByIdWithDetailsAsync(id);
            if (assignment == null)
                return NotFound();

            var assignmentDto = _mapper.Map<AssignmentDTO>(assignment);
            return Ok(assignmentDto);
        }

        [HttpGet("course/{courseId}")]
        public async Task<IActionResult> GetByCourse(int courseId)
        {
            // kullanıcı kursu almış mı kontrol et
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var isTeacher = User.IsInRole("Teacher");
            var isAdmin = User.IsInRole("Admin");
            var isStudent = User.IsInRole("Student");

            // admim erişimine izin verme
            if (!isAdmin)
            {
                if (isTeacher)
                {
                   
                    var course = await _courseRepository.GetByIdAsync(courseId);
                    if (course == null || course.TeacherId != userId)
                        return Forbid();
                }
                else if (isStudent)
                {
                    // öğrenci kursu almış mı kontrol et
                    var isEnrolled = await _context.StudentCourse
                        .AnyAsync(sc => sc.StudentId == userId && sc.CourseId == courseId && sc.IsActive);

                    if (!isEnrolled)
                        return Forbid();
                }
            }

            var assignments = await _assignmentRepository.GetAssignmentsByCourseAsync(courseId);
            var assignmentDtos = _mapper.Map<IEnumerable<AssignmentDTO>>(assignments);
            return Ok(assignmentDtos);
        }

        [HttpGet("teacher")]
        [Authorize(Roles = "Teacher")]
        public async Task<IActionResult> GetByTeacher()
        {
            var teacherId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var assignments = await _assignmentRepository.GetAssignmentsByTeacherAsync(teacherId);
            var assignmentDtos = _mapper.Map<IEnumerable<AssignmentDTO>>(assignments);
            return Ok(assignmentDtos);
        }

        [HttpGet("student")]
        [Authorize(Roles = "Student")]
        public async Task<IActionResult> GetByStudent()
        {
            var studentId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var assignments = await _assignmentRepository.GetAssignmentsByStudentAsync(studentId);
            var assignmentDtos = _mapper.Map<IEnumerable<AssignmentDTO>>(assignments);
            return Ok(assignmentDtos);
        }

        [Authorize(Roles = "Teacher,Admin")]
        [HttpPost]
        public async Task<IActionResult> Create([FromBody] AssignmentCreateDTO assignmentDto)
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var isAdmin = User.IsInRole("Admin");

            // kurs var mı konttol et
            var course = await _courseRepository.GetByIdAsync(assignmentDto.CourseId);
            if (course == null)
                return NotFound(new { Message = "Course not found" });

            // kullanıcı öğretmen veya admin mi kontrol et
            if (!isAdmin && course.TeacherId != userId)
                return Forbid();

            var assignment = _mapper.Map<Assignment>(assignmentDto);
            await _assignmentRepository.AddAsync(assignment);

            // kursu alan öğrencileri bilgilendir
            var enrolledStudents = await _context.StudentCourse
                .Where(sc => sc.CourseId == assignmentDto.CourseId && sc.IsActive)
                .Select(sc => sc.StudentId)
                .ToListAsync();

            foreach (var studentId in enrolledStudents)
            {
                var notification = new Notification
                {
                    Title = "New Assignment",
                    Message = $"A new assignment '{assignmentDto.Title}' has been posted for {course.Name}.",
                    UserId = studentId,
                    NotificationType = "Assignment"
                };

                await _notificationRepository.AddAsync(notification);
            }

            var assignmentDtoResult = _mapper.Map<AssignmentDTO>(assignment);
            return CreatedAtAction(nameof(GetById), new { id = assignment.Id }, assignmentDtoResult);
        }

        [Authorize(Roles = "Teacher,Admin")]
        [HttpPut]
        public async Task<IActionResult> Update([FromBody] AssignmentUpdateDTO assignmentDto)
        {
            var existingAssignment = await _assignmentRepository.GetByIdWithDetailsAsync(assignmentDto.Id);
            if (existingAssignment == null)
                return NotFound();

            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var isAdmin = User.IsInRole("Admin");

            // sadece admin ve öğretmen kursu güncelleyebilir kontrol et rolü
            if (!isAdmin && existingAssignment.Course.TeacherId != userId)
                return Forbid();

            _mapper.Map(assignmentDto, existingAssignment);
            await _assignmentRepository.UpdateAsync(existingAssignment);

            // kurs güncellendiğinde öğrencilere bildirim gönder
            var enrolledStudents = await _context.StudentCourse
                .Where(sc => sc.CourseId == existingAssignment.CourseId && sc.IsActive)
                .Select(sc => sc.StudentId)
                .ToListAsync();

            foreach (var studentId in enrolledStudents)
            {
                var notification = new Notification
                {
                    Title = "Assignment Updated",
                    Message = $"Assignment '{existingAssignment.Title}' has been updated.",
                    UserId = studentId,
                    NotificationType = "Assignment"
                };

                await _notificationRepository.AddAsync(notification);
            }

            return NoContent();
        }

        [Authorize(Roles = "Teacher,Admin")]
        [HttpDelete("{id}")]
        public async Task<IActionResult> Delete(int id)
        {
            var assignment = await _assignmentRepository.GetByIdWithDetailsAsync(id);
            if (assignment == null)
                return NotFound();

            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var isAdmin = User.IsInRole("Admin");

            // Only the teacher of the course or an admin can delete an assignment
            if (!isAdmin && assignment.Course.TeacherId != userId)
                return Forbid();

            var result = await _assignmentRepository.DeleteAsync(id);
            if (!result)
                return NotFound();

            return NoContent();
        }
    }
}