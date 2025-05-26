using OdevPortalAPI.Models;
using Microsoft.EntityFrameworkCore;

namespace OdevPortalAPI.Repositories
{
    public class CourseRepository : GenericRepository<Course>
    {
        public CourseRepository(AppDbContext context) : base(context)
        {
        }

        public async Task<IEnumerable<Course>> GetAllWithDetailsAsync()
        {
            return await _dbSet
                .Include(c => c.Department)
                .Include(c => c.Teacher)
                .Where(c => c.IsActive)
                .ToListAsync();
        }

        public async Task<Course> GetByIdWithDetailsAsync(int id)
        {
            return await _dbSet
                .Include(c => c.Department)
                .Include(c => c.Teacher)
                .Include(c => c.Assignments)
                .FirstOrDefaultAsync(c => c.Id == id && c.IsActive);
        }

        public async Task<IEnumerable<Course>> GetCoursesByDepartmentAsync(int departmentId)
        {
            return await _dbSet
                .Include(c => c.Teacher)
                .Where(c => c.IsActive && c.DepartmentId == departmentId)
                .ToListAsync();
        }

        public async Task<IEnumerable<Course>> GetCoursesByTeacherAsync(string teacherId)
        {
            return await _dbSet
                .Include(c => c.Department)
                .Where(c => c.IsActive && c.TeacherId == teacherId)
                .ToListAsync();
        }

        public async Task<IEnumerable<Course>> GetCoursesByStudentAsync(string studentId)
        {
            return await _context.StudentCourse
                .Where(sc => sc.StudentId == studentId)
                .Include(sc => sc.Course)
                .ThenInclude(c => c.Department)
                .Include(sc => sc.Course)
                .ThenInclude(c => c.Teacher)
                .Select(sc => sc.Course)
                .Where(c => c.IsActive)
                .ToListAsync();
        }
    }
}