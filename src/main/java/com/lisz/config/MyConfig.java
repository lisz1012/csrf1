package com.lisz.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class MyConfig extends WebSecurityConfigurerAdapter {
	// 默认情况下，重写configure方法就已经开启了csrf验证，回去检查表单里有没有_csrf.token。不写
	// 下面下发hash值，Controller下发到页面上，项目后端也要存这个哈希值
	// configure方法就是提供给我们重新配置属性的
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests().anyRequest().authenticated()
		.and()
		.formLogin().loginPage("/login.html")  // 登陆表单
				.loginProcessingUrl("/login")
				.permitAll()
				.failureForwardUrl("/error.html")
				.defaultSuccessUrl("/login_success.html", true)
				.usernameParameter("aaa") // Spring Security会拿着 aaa去寻找html中name="aaa"的那个input，将其value作为username
				.passwordParameter("bbb") // Spring Security会拿着 bbb去寻找html中name="bbb"的那个input，将其value作为password, 并校验能否分别对上yml中设置的spring.security.user.name和spring.security.user.password
				.failureHandler(new AuthenticationFailureHandler() {
					@Override
					public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
						exception.printStackTrace();
						//登录的时候账号或密码出错，则会抛出BadCredentialsException，可以用instanceof判断各种情况作出处理
						if (exception instanceof CredentialsExpiredException ||
								exception instanceof LockedException ||
								exception instanceof BadCredentialsException) {
							request.getSession().setAttribute("errorMessage", exception.getMessage());
						} else if (exception.getCause() instanceof CredentialsExpiredException ||
								exception.getCause() instanceof LockedException ||
								exception.getCause() instanceof BadCredentialsException) {
							request.getSession().setAttribute("errorMessage", exception.getCause().getMessage());
						}
						request.getRequestDispatcher(request.getRequestURL().toString()).forward(request, response);
						// 记录登录失败次数 禁止登录
					}
				})
//				.authorizeRequests()
//				.antMatchers("").denyAll()
				// 默认所有post请求都拦截需要校验
				.and() // and就退回父标签了
				.csrf().csrfTokenRepository(new HttpSessionCsrfTokenRepository());
//				.and()

	}
}
