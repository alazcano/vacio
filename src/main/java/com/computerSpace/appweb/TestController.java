package com.computerSpace.appweb;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
@Controller
@RequestMapping("/")
public class TestController {

	@GetMapping
	public String test()
	{
		return "inicio";
	}
	@RequestMapping(value="/marketing")
	public String marketing(){
		return "marketing";
	}
	@RequestMapping(value="/desarrollo")
	public String desarrollo(){
		return "desarrollo";
	}
	@RequestMapping(value="/admin")
	public String admin(){
		return "admin";
	}
	@RequestMapping(value="/403")
	public String error(){
		return "loginerror";
	}
	@RequestMapping(value="/logout")
	public String logout(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse){
		Authentication auth=SecurityContextHolder.getContext().getAuthentication();
		String user=httpServletRequest.getRemoteUser();//para sacar el nombre del usuario
		if (auth!=null) {
			new SecurityContextLogoutHandler().logout(httpServletRequest, httpServletResponse, auth);
		}
		return "redirect:/";
	}
}
