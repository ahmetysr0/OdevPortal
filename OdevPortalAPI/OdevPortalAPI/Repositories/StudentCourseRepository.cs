using OdevPortalAPI.Models;
using OdevPortalAPI.Repositories;
using Microsoft.EntityFrameworkCore;

public class StudentCourseRepository : GenericRepository<StudentCourse>
{
    public StudentCourseRepository(AppDbContext context) : base(context)
    {
    }

    public async Task<bool> IsStudentEnrolledAsync(string studentId, int courseId)
    {
        return await _dbSet.AnyAsync(sc => sc.StudentId == studentId && sc.CourseId == courseId && sc.IsActive);
    }
}