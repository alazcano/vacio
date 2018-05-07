package com.computerSpace.appweb;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
	@Autowired
	private AccessDeniedHandler accessDeniedHandler;
	
	@Override
	protected void configure(HttpSecurity http)throws Exception{	
		http.csrf().disable().authorizeRequests()
		.antMatchers("/").permitAll()
		.antMatchers("/marketing").hasAnyRole("MAR")
		.antMatchers("/desarrollo").hasAnyRole("DES")
		.antMatchers("/admin").hasAnyRole("ADMIN")
		.anyRequest().authenticated()
		.and().formLogin().permitAll()
		.and().logout().permitAll().logoutRequestMatcher(new AntPathRequestMatcher("/LogOut")).logoutSuccessUrl("/")
		.and().exceptionHandling().accessDeniedHandler(accessDeniedHandler);
	}
	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth)throws Exception{
		BCryptPasswordEncoder encoder = passworEncoder();
		auth.inMemoryAuthentication()
		.withUser("user").password(encoder.encode("1234")).roles("USER")
		.and()
		.withUser("user2").password(encoder.encode("1111")).roles("USER")
		.and()
		.withUser("mar1").password(encoder.encode("mar1")).roles("MAR")
		.and()
		.withUser("des1").password(encoder.encode("des1")).roles("DES")
		.and()
		.withUser("admin").password(encoder.encode("2222")).roles("ADMIN");
	}
	@Bean
	public BCryptPasswordEncoder passworEncoder(){
		return new BCryptPasswordEncoder();
	}
}
