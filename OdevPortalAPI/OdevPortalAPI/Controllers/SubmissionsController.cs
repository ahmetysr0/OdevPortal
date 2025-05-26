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
    public class SubmissionsController : ControllerBase
    {
        private readonly SubmissionRepository _submissionRepository;
        private readonly AssignmentRepository _assignmentRepository;
        private readonly NotificationRepository _notificationRepository;
        private readonly AppDbContext _context;
        private readonly IMapper _mapper;

        public SubmissionsController(
            SubmissionRepository submissionRepository,
            AssignmentRepository assignmentRepository,
            NotificationRepository notificationRepository,
            AppDbContext context,
            IMapper mapper)
        {
            _submissionRepository = submissionRepository;
            _assignmentRepository = assignmentRepository;
            _notificationRepository = notificationRepository;
            _context = context;
            _mapper = mapper;
        }

        
        [HttpGet]
        [Authorize(Roles = "Teacher,Admin")]
        public async Task<IActionResult> GetAll()
        {
            var submissions = await _submissionRepository.GetAllWithDetailsAsync();
            var submissionDtos = _mapper.Map<IEnumerable<SubmissionDTO>>(submissions);
            return Ok(submissionDtos);
        }

        
        [HttpGet("{id}")]
        public async Task<IActionResult> GetById(int id)
        {
            var submission = await _submissionRepository.GetByIdWithDetailsAsync(id);
            if (submission == null)
                return NotFound();

            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var isTeacher = User.IsInRole("Teacher");
            var isAdmin = User.IsInRole("Admin");

            // Only the submission owner, the course teacher, or an admin can view a submission
            if (submission.StudentId != userId &&
                !isAdmin &&
                !(isTeacher && submission.Assignment.Course.TeacherId == userId))
                return Forbid();

            var submissionDto = _mapper.Map<SubmissionDTO>(submission);
            return Ok(submissionDto);
        }

        [HttpGet("assignment/{assignmentId}")]
        [Authorize(Roles = "Teacher,Admin")]
        public async Task<IActionResult> GetByAssignment(int assignmentId)
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var isAdmin = User.IsInRole("Admin");

            // Verify the assignment exists
            var assignment = await _assignmentRepository.GetByIdWithDetailsAsync(assignmentId);
            if (assignment == null)
                return NotFound(new { Message = "Assignment not found" });

            // Only the course teacher or an admin can view all submissions for an assignment
            if (!isAdmin && assignment.Course.TeacherId != userId)
                return Forbid();

            var submissions = await _submissionRepository.GetSubmissionsByAssignmentAsync(assignmentId);
            var submissionDtos = _mapper.Map<IEnumerable<SubmissionDTO>>(submissions);
            return Ok(submissionDtos);
        }

        [HttpGet("student")]
        [Authorize(Roles = "Student")]
        public async Task<IActionResult> GetByStudent()
        {
            var studentId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var submissions = await _submissionRepository.GetSubmissionsByStudentAsync(studentId);
            var submissionDtos = _mapper.Map<IEnumerable<SubmissionDTO>>(submissions);
            return Ok(submissionDtos);
        }

        [HttpGet("student/{studentId}/assignment/{assignmentId}")]
        public async Task<IActionResult> GetByStudentAndAssignment(string studentId, int assignmentId)
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var isTeacher = User.IsInRole("Teacher");
            var isAdmin = User.IsInRole("Admin");

            // Only the submission owner, the course teacher, or an admin can view a submission
            if (studentId != userId && !isAdmin && !isTeacher)
                return Forbid();

            // If teacher, verify they teach the course
            if (isTeacher && !isAdmin)
            {
                var assignment = await _assignmentRepository.GetByIdWithDetailsAsync(assignmentId);
                if (assignment == null || assignment.Course.TeacherId != userId)
                    return Forbid();
            }

            var submission = await _submissionRepository.GetSubmissionByStudentAndAssignmentAsync(studentId, assignmentId);
            if (submission == null)
                return NotFound();

            var submissionDto = _mapper.Map<SubmissionDTO>(submission);
            return Ok(submissionDto);
        }

        [Authorize(Roles = "Student")]
        [HttpPost]
        public async Task<IActionResult> Create([FromBody] SubmissionCreateDTO submissionDto)
        {
            var studentId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            // Verify assignment exists
            var assignment = await _assignmentRepository.GetByIdWithDetailsAsync(submissionDto.AssignmentId);
            if (assignment == null)
                return NotFound(new { Message = "Assignment not found" });

            // Check if student is enrolled in the course
            var isEnrolled = await _context.StudentCourse
                .AnyAsync(sc => sc.StudentId == studentId && sc.CourseId == assignment.CourseId && sc.IsActive);

            if (!isEnrolled)
                return Forbid();

            // Check if due date has passed
            if (DateTime.Now > assignment.DueDate)
                return BadRequest(new { Message = "The due date for this assignment has passed" });

            // Check if student already submitted
            var existingSubmission = await _submissionRepository.GetSubmissionByStudentAndAssignmentAsync(studentId, submissionDto.AssignmentId);
            if (existingSubmission != null)
                return BadRequest(new { Message = "You have already submitted for this assignment" });

            var submission = _mapper.Map<Submission>(submissionDto);
            submission.StudentId = studentId;
            submission.SubmissionDate = DateTime.Now;

            await _submissionRepository.AddAsync(submission);

            // Notify the teacher
            var notification = new Notification
            {
                Title = "New Submission",
                Message = $"A new submission has been received for assignment '{assignment.Title}'",
                UserId = assignment.Course.TeacherId,
                NotificationType = "Submission"
            };

            await _notificationRepository.AddAsync(notification);

            var submissionDtoResult = _mapper.Map<SubmissionDTO>(submission);
            return CreatedAtAction(nameof(GetById), new { id = submission.Id }, submissionDtoResult);
        }

        [Authorize(Roles = "Student")]
        [HttpPut]
        public async Task<IActionResult> Update([FromBody] SubmissionUpdateDTO submissionDto)
        {
            var existingSubmission = await _submissionRepository.GetByIdWithDetailsAsync(submissionDto.Id);
            if (existingSubmission == null)
                return NotFound();

            var studentId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            // Only the submission owner can update it
            if (existingSubmission.StudentId != studentId)
                return Forbid();

            // Check if the submission has already been graded
            if (existingSubmission.IsGraded)
                return BadRequest(new { Message = "Cannot update a submission that has already been graded" });

            // Check if due date has passed
            if (DateTime.Now > existingSubmission.Assignment.DueDate)
                return BadRequest(new { Message = "The due date for this assignment has passed" });

            _mapper.Map(submissionDto, existingSubmission);
            existingSubmission.SubmissionDate = DateTime.Now;

            await _submissionRepository.UpdateAsync(existingSubmission);

            // Notify the teacher
            var notification = new Notification
            {
                Title = "Submission Updated",
                Message = $"A submission for assignment '{existingSubmission.Assignment.Title}' has been updated",
                UserId = existingSubmission.Assignment.Course.TeacherId,
                NotificationType = "Submission"
            };

            await _notificationRepository.AddAsync(notification);

            return NoContent();
        }

        [Authorize(Roles = "Teacher,Admin")]
        [HttpPost("grade")]
        public async Task<IActionResult> GradeSubmission([FromBody] GradeSubmissionDTO gradeDto)
        {
            var submission = await _submissionRepository.GetByIdWithDetailsAsync(gradeDto.Id);
            if (submission == null)
                return NotFound();

            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var isAdmin = User.IsInRole("Admin");

            // Only the course teacher or an admin can grade a submission
            if (!isAdmin && submission.Assignment.Course.TeacherId != userId)
                return Forbid();

            // Validate score
            if (gradeDto.Score < 0 || gradeDto.Score > submission.Assignment.TotalPoints)
                return BadRequest(new { Message = $"Score must be between 0 and {submission.Assignment.TotalPoints}" });

            _mapper.Map(gradeDto, submission);
            submission.IsGraded = true;

            await _submissionRepository.UpdateAsync(submission);

            // Notify the student
            var notification = new Notification
            {
                Title = "Submission Graded",
                Message = $"Your submission for assignment '{submission.Assignment.Title}' has been graded",
                UserId = submission.StudentId,
                NotificationType = "Grade"
            };

            await _notificationRepository.AddAsync(notification);

            return Ok(new { Message = "Submission graded successfully" });
        }

        [Authorize(Roles = "Student")]
        [HttpDelete("{id}")]
        public async Task<IActionResult> Delete(int id)
        {
            var submission = await _submissionRepository.GetByIdWithDetailsAsync(id);
            if (submission == null)
                return NotFound();

            var studentId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            // Only the submission owner can delete it
            if (submission.StudentId != studentId)
                return Forbid();

            // Check if the submission has already been graded
            if (submission.IsGraded)
                return BadRequest(new { Message = "Cannot delete a submission that has already been graded" });

            // Check if due date has passed
            if (DateTime.Now > submission.Assignment.DueDate)
                return BadRequest(new { Message = "The due date for this assignment has passed" });

            var result = await _submissionRepository.DeleteAsync(id);
            if (!result)
                return NotFound();

            return NoContent();
        }
    }
}