package com.lisz.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class LoginController {
	@GetMapping("/login.html")
	public String loginHtml(){
		return "login";
	}

	@PostMapping("/login")
	public String login(){
		return "login_success";
	}
}
