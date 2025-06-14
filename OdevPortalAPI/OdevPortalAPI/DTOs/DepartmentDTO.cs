﻿namespace OdevPortalAPI.DTOs
{
    public class DepartmentDTO
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
    }

    public class DepartmentCreateDTO
    {
        public string Name { get; set; }
        public string Description { get; set; }
    }

    public class DepartmentUpdateDTO
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
    }
}