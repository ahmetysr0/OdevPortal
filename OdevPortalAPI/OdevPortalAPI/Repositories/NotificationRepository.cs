using OdevPortalAPI.Models;
using Microsoft.EntityFrameworkCore;

namespace OdevPortalAPI.Repositories
{
    public class NotificationRepository : GenericRepository<Notification>
    {
        public NotificationRepository(AppDbContext context) : base(context)
        {
        }

        public async Task<IEnumerable<Notification>> GetNotificationsByUserAsync(string userId)
        {
            return await _dbSet
                .Where(n => n.IsActive && n.UserId == userId)
                .OrderByDescending(n => n.CreatedDate)
                .ToListAsync();
        }

        public async Task<IEnumerable<Notification>> GetUnreadNotificationsByUserAsync(string userId)
        {
            return await _dbSet
                .Where(n => n.IsActive && n.UserId == userId && !n.IsRead)
                .OrderByDescending(n => n.CreatedDate)
                .ToListAsync();
        }

        public async Task<int> MarkAllAsReadAsync(string userId)
        {
            var notifications = await _dbSet
                .Where(n => n.IsActive && n.UserId == userId && !n.IsRead)
                .ToListAsync();

            foreach (var notification in notifications)
            {
                notification.IsRead = true;
                notification.ModifiedDate = DateTime.Now;
            }

            return await _context.SaveChangesAsync();
        }
    }
}