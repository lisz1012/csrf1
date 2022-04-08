package com.lisz.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MainController {
	@GetMapping("/hi")
	public String hi(){
		System.out.println("来了老弟");
		return "hi";
	}


}
