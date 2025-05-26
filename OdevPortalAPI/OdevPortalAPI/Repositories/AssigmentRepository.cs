using OdevPortalAPI.Models;
using Microsoft.EntityFrameworkCore;

namespace OdevPortalAPI.Repositories
{
    public class AssignmentRepository : GenericRepository<Assignment>
    {
        public AssignmentRepository(AppDbContext context) : base(context)
        {
        }

        public async Task<IEnumerable<Assignment>> GetAllWithDetailsAsync()
        {
            return await _dbSet
                .Include(a => a.Course)
                .Where(a => a.IsActive)
                .ToListAsync();
        }

        public async Task<Assignment> GetByIdWithDetailsAsync(int id)
        {
            return await _dbSet
                .Include(a => a.Course)
                .Include(a => a.Submissions)
                .FirstOrDefaultAsync(a => a.Id == id && a.IsActive);
        }

        public async Task<IEnumerable<Assignment>> GetAssignmentsByCourseAsync(int courseId)
        {
            return await _dbSet
                .Where(a => a.IsActive && a.CourseId == courseId)
                .ToListAsync();
        }

        public async Task<IEnumerable<Assignment>> GetAssignmentsByStudentAsync(string studentId)
        {
            var studentCourses = await _context.StudentCourse
                .Where(sc => sc.StudentId == studentId)
                .Select(sc => sc.CourseId)
                .ToListAsync();

            return await _dbSet
                .Include(a => a.Course)
                .Where(a => a.IsActive && studentCourses.Contains(a.CourseId))
                .ToListAsync();
        }

        public async Task<IEnumerable<Assignment>> GetAssignmentsByTeacherAsync(string teacherId)
        {
            return await _dbSet
                .Include(a => a.Course)
                .Where(a => a.IsActive && a.Course.TeacherId == teacherId)
                .ToListAsync();
        }
    }
}