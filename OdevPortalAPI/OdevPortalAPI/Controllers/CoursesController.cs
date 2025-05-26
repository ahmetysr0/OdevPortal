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
    public class CoursesController : ControllerBase
    {
        private readonly CourseRepository _courseRepository;
        private readonly StudentCourseRepository _studentCourseRepository;
        private readonly AppDbContext _context;
        private readonly IMapper _mapper;

        public CoursesController(
            CourseRepository courseRepository,
            StudentCourseRepository studentCourseRepository,
            AppDbContext context,
            IMapper mapper)
        {
            _courseRepository = courseRepository;
            _studentCourseRepository = studentCourseRepository;
            _context = context;
            _mapper = mapper;
        }

        // kurs listeleme metodu

        [HttpGet]
        public async Task<IActionResult> GetAll()
        {
            var courses = await _courseRepository.GetAllWithDetailsAsync();
            var courseDtos = _mapper.Map<IEnumerable<CourseDTO>>(courses);
            return Ok(courseDtos);
        }

        // idye göre kurs listeleme

        [HttpGet("{id}")]
        public async Task<IActionResult> GetById(int id)
        {
            var course = await _courseRepository.GetByIdWithDetailsAsync(id);
            if (course == null)
                return NotFound();

            var courseDto = _mapper.Map<CourseDTO>(course);
            return Ok(courseDto);
        }

        // departmentId'ye göre kurs listeleme

        [HttpGet("department/{departmentId}")]
        public async Task<IActionResult> GetByDepartment(int departmentId)
        {
            var courses = await _courseRepository.GetCoursesByDepartmentAsync(departmentId);
            var courseDtos = _mapper.Map<IEnumerable<CourseDTO>>(courses);
            return Ok(courseDtos);
        }

        // teacherId'ye göre kurs listeleme

        [HttpGet("teacher")]
        [Authorize(Roles = "Teacher,Admin")]
        public async Task<IActionResult> GetByTeacher()
        {
            var teacherId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var courses = await _courseRepository.GetCoursesByTeacherAsync(teacherId);
            var courseDtos = _mapper.Map<IEnumerable<CourseDTO>>(courses);
            return Ok(courseDtos);
        }

        // studentId'ye göre kurs listeleme

        [HttpGet("student")]
        [Authorize(Roles = "Student,Admin")]
        public async Task<IActionResult> GetByStudent()
        {
            var studentId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var courses = await _courseRepository.GetCoursesByStudentAsync(studentId);
            var courseDtos = _mapper.Map<IEnumerable<CourseDTO>>(courses);
            return Ok(courseDtos);
        }

        // kurs oluşturma metodu

        [Authorize(Roles = "Admin,Teacher")]
        [HttpPost]
        public async Task<IActionResult> Create([FromBody] CourseCreateDTO courseDto)
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var isAdmin = User.IsInRole("Admin");
            var teacherId = isAdmin ? courseDto.TeacherId : userId;

            var course = _mapper.Map<Course>(courseDto);
            course.TeacherId = teacherId;

            await _courseRepository.AddAsync(course);
            var courseDtoResult = _mapper.Map<CourseDTO>(course);
            return CreatedAtAction(nameof(GetById), new { id = course.Id }, courseDtoResult);
        }

        // kurs güncelleme metodu

        [Authorize(Roles = "Admin,Teacher")]
        [HttpPut]
        public async Task<IActionResult> Update([FromBody] CourseUpdateDTO courseDto)
        {
            var existingCourse = await _courseRepository.GetByIdAsync(courseDto.Id);
            if (existingCourse == null)
                return NotFound();

            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var isAdmin = User.IsInRole("Admin");

            // sadece öğretmen ve admin kursu güncelleyebilir kontrol et rolü
            if (existingCourse.TeacherId != userId && !isAdmin)
                return Forbid();

            _mapper.Map(courseDto, existingCourse);

            // sadece admin öğretmeni değiştirebilir
            if (!isAdmin)
                existingCourse.TeacherId = userId; 

            await _courseRepository.UpdateAsync(existingCourse);
            return NoContent();
        }
        // kurs silme metodu

        [Authorize(Roles = "Admin")]
        [HttpDelete("{id}")]
        public async Task<IActionResult> Delete(int id)
        {
            var result = await _courseRepository.DeleteAsync(id);
            if (!result)
                return NotFound();

            return NoContent();
        }
        // kursa kayıt olma metodu

        [HttpPost("enroll/{courseId}")]
        [Authorize(Roles = "Student")]
        public async Task<IActionResult> EnrollCourse(int courseId)
        {
            var studentId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

          
            var course = await _courseRepository.GetByIdAsync(courseId);
            if (course == null)
                return NotFound(new { Message = "Course not found" });

 
            var alreadyEnrolled = await _context.StudentCourse
                .AnyAsync(sc => sc.StudentId == studentId && sc.CourseId == courseId && sc.IsActive);

            if (alreadyEnrolled)
                return BadRequest(new { Message = "Already enrolled in this course" });

            var studentCourse = new StudentCourse
            {
                StudentId = studentId,
                CourseId = courseId,
                EnrollmentDate = DateTime.Now
            };

            await _studentCourseRepository.AddAsync(studentCourse);

            return Ok(new { Message = "Successfully enrolled in course" });
        }

        // kurs kaydını iptal etme metodu

        [HttpDelete("unenroll/{courseId}")]
        [Authorize(Roles = "Student")]
        public async Task<IActionResult> UnenrollCourse(int courseId)
        {
            var studentId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            var enrollments = await _context.StudentCourse
                .Where(sc => sc.StudentId == studentId && sc.CourseId == courseId && sc.IsActive)
                .ToListAsync();

            if (!enrollments.Any())
                return NotFound(new { Message = "Not enrolled in this course" });

            foreach (var enrollment in enrollments)
            {
                await _studentCourseRepository.DeleteAsync(enrollment.Id);
            }

            return Ok(new { Message = "Successfully unenrolled from course" });
        }
    }
}