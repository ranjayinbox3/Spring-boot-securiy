package com.springsecurity.springsecuritydemo.controller;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.springsecurity.springsecuritydemo.entity.Student;
@RestController
@RequestMapping(value= "/management/api/v1/student")
public class StudentManagementController {
	
	//hasRole('ROLE_'), hasAnyRole('ROLE_'),hasAuthority('permission'),hasAnyAuthority('permission')
		
		@GetMapping(value = "/getStudent")
		//@PreAuthorize("hasRole('ROLE_ADMIN','ROLE_ADMINTRAINEE')")
		public Student getStudent() {
			Student emp = new Student();
			emp.setStudentId(100);
			emp.setFname("Ranjay");
			emp.setLname("Singh");
			return emp;
		}
		
		@DeleteMapping(path = "/deleteStudent/{studentId}")
		//@PreAuthorize("hasAuthority('student:write')")
		public String deleteStudent(@PathVariable Integer studentId) {
			return "Student deleted of Id "+studentId;
		}
		
		@PostMapping(value = "/registerStudent")
		//@PreAuthorize("hasAuthority('student:write')")
		public String registerStudent(@RequestBody Student student) {
			return "Student Registered of Id "+student.getStudentId()+" name "+student.getFname();
		}

}
