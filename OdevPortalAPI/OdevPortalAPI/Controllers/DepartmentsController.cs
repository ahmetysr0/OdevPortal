using OdevPortalAPI.DTOs;
using OdevPortalAPI.Models;
using OdevPortalAPI.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using AutoMapper;

namespace OdevPortalAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class DepartmentsController : ControllerBase
    {
        private readonly GenericRepository<Department> _departmentRepository;
        private readonly IMapper _mapper;

        public DepartmentsController(GenericRepository<Department> departmentRepository, IMapper mapper)
        {
            _departmentRepository = departmentRepository;
            _mapper = mapper;
        }
        // departmentId'ye göre kurs listeleme

        [HttpGet]
        public async Task<IActionResult> GetAll()
        {
            var departments = await _departmentRepository.GetAllAsync();
            var departmentDtos = _mapper.Map<IEnumerable<DepartmentDTO>>(departments);
            return Ok(departmentDtos);
        }
        // departmentId'ye göre kurs listeleme

        [HttpGet("{id}")]
        public async Task<IActionResult> GetById(int id)
        {
            var department = await _departmentRepository.GetByIdAsync(id);
            if (department == null)
                return NotFound();

            var departmentDto = _mapper.Map<DepartmentDTO>(department);
            return Ok(departmentDto);
        }

        // departmentId'ye göre kurs listeleme
        [Authorize(Roles = "Admin")]
        [HttpPost]
        public async Task<IActionResult> Create([FromBody] DepartmentCreateDTO departmentDto)
        {
            var department = _mapper.Map<Department>(departmentDto);
            await _departmentRepository.AddAsync(department);

            var departmentDtoResult = _mapper.Map<DepartmentDTO>(department);
            return CreatedAtAction(nameof(GetById), new { id = department.Id }, departmentDtoResult);
        }

        // departmentId'ye göre kurs listeleme

        [Authorize(Roles = "Admin")]
        [HttpPut]
        public async Task<IActionResult> Update([FromBody] DepartmentUpdateDTO departmentDto)
        {
            var existingDepartment = await _departmentRepository.GetByIdAsync(departmentDto.Id);
            if (existingDepartment == null)
                return NotFound();

            _mapper.Map(departmentDto, existingDepartment);
            await _departmentRepository.UpdateAsync(existingDepartment);
            return NoContent();
        }
        // departmentId'ye göre kurs listeleme

        [Authorize(Roles = "Admin")]
        [HttpDelete("{id}")]
        public async Task<IActionResult> Delete(int id)
        {
            var result = await _departmentRepository.DeleteAsync(id);
            if (!result)
                return NotFound();

            return NoContent();
        }
    }
}