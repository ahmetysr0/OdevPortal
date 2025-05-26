using OdevPortalAPI.DTOs;
using OdevPortalAPI.Models;
using OdevPortalAPI.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using AutoMapper;

namespace OdevPortalAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class NotificationsController : ControllerBase
    {
        private readonly NotificationRepository _notificationRepository;
        private readonly IMapper _mapper;

        public NotificationsController(NotificationRepository notificationRepository, IMapper mapper)
        {
            _notificationRepository = notificationRepository;
            _mapper = mapper;
        }
        // Kullanıcıya ait bildirimleri listeleme

        [HttpGet]
        public async Task<IActionResult> GetUserNotifications()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var notifications = await _notificationRepository.GetNotificationsByUserAsync(userId);
            var notificationDtos = _mapper.Map<IEnumerable<NotificationDTO>>(notifications);
            return Ok(notificationDtos);
        }

        // Kullanıcıya ait okunmamış bildirimleri listeleme
        [HttpGet("unread")]
        public async Task<IActionResult> GetUnreadNotifications()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var notifications = await _notificationRepository.GetUnreadNotificationsByUserAsync(userId);
            var notificationDtos = _mapper.Map<IEnumerable<NotificationDTO>>(notifications);
            return Ok(notificationDtos);
        }
        // Kullanıcıya ait bildirimleri id'ye göre listeleme

        [HttpPut("read/{id}")]
        public async Task<IActionResult> MarkAsRead(int id)
        {
            var notification = await _notificationRepository.GetByIdAsync(id);
            if (notification == null)
                return NotFound();

            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (notification.UserId != userId)
                return Forbid();

            notification.IsRead = true;
            await _notificationRepository.UpdateAsync(notification);

            return NoContent();
        }
        // Kullanıcıya ait bildirimleri id'ye göre listeleme

        [HttpPut("read-all")]
        public async Task<IActionResult> MarkAllAsRead()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var count = await _notificationRepository.MarkAllAsReadAsync(userId);

            return Ok(new { Message = $"{count} notifications marked as read" });
        }

        // Kullanıcıya ait bildirimleri id'ye göre listeleme
        [Authorize(Roles = "Admin,Teacher")]
        [HttpPost]
        public async Task<IActionResult> CreateNotification([FromBody] NotificationCreateDTO notificationDto)
        {
            var notification = _mapper.Map<Notification>(notificationDto);
            await _notificationRepository.AddAsync(notification);
            return Ok(new { Message = "Notification created successfully" });
        }
    }
}