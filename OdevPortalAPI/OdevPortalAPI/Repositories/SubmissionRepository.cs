using OdevPortalAPI.Models;
using Microsoft.EntityFrameworkCore;

namespace OdevPortalAPI.Repositories
{
    public class SubmissionRepository : GenericRepository<Submission>
    {
        public SubmissionRepository(AppDbContext context) : base(context)
        {
        }

        public async Task<IEnumerable<Submission>> GetAllWithDetailsAsync()
        {
            return await _dbSet
                .Include(s => s.Assignment)
                .Include(s => s.Student)
                .Where(s => s.IsActive)
                .ToListAsync();
        }

        public async Task<Submission> GetByIdWithDetailsAsync(int id)
        {
            return await _dbSet
                .Include(s => s.Assignment)
                .Include(s => s.Student)
                .FirstOrDefaultAsync(s => s.Id == id && s.IsActive);
        }

        public async Task<IEnumerable<Submission>> GetSubmissionsByAssignmentAsync(int assignmentId)
        {
            return await _dbSet
                .Include(s => s.Student)
                .Where(s => s.IsActive && s.AssignmentId == assignmentId)
                .ToListAsync();
        }

        public async Task<IEnumerable<Submission>> GetSubmissionsByStudentAsync(string studentId)
        {
            return await _dbSet
                .Include(s => s.Assignment)
                .ThenInclude(a => a.Course)
                .Where(s => s.IsActive && s.StudentId == studentId)
                .ToListAsync();
        }

        public async Task<Submission> GetSubmissionByStudentAndAssignmentAsync(string studentId, int assignmentId)
        {
            return await _dbSet
                .Include(s => s.Assignment)
                .FirstOrDefaultAsync(s => s.IsActive && s.StudentId == studentId && s.AssignmentId == assignmentId);
        }
    }
}