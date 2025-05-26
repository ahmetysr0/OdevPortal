namespace OdevPortalAPI.DTOs
{
    public class NotificationDTO
    {
        public int Id { get; set; }
        public string Title { get; set; }
        public string Message { get; set; }
        public bool IsRead { get; set; }
        public string UserId { get; set; }
        public string NotificationType { get; set; }
    }

    public class NotificationCreateDTO
    {
        public string Title { get; set; }
        public string Message { get; set; }
        public string UserId { get; set; }
        public string NotificationType { get; set; }
    }

    public class NotificationUpdateDTO
    {
        public int Id { get; set; }
        public bool IsRead { get; set; }
    }
}