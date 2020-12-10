package com.springsecurity.springsecuritydemo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.springsecurity.springsecuritydemo.entity.Student;

@RestController
@RequestMapping(value= "/api/v1/student")
public class StudentController {
	
	@GetMapping(value = "/getStudent")
	public Student getStudent() {
		Student emp = new Student();
		emp.setStudentId(100);
		emp.setFname("Ranjay");
		emp.setLname("Singh");
		return emp;
	}

}
