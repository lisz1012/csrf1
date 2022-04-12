package com.lisz.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
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
	// 下面下发hash值，Controller下发到页面上，项目后端也要存这个哈希值。客户端提交的时候要带回这个哈希值
	// 这个Hash值不能放在cookie里，否则就会被偷到
	// configure方法就是提供给我们重新配置属性的。
	// 这个 Spring Security更多的适用于单机，不是分布式
	@Override
	protected void configure(HttpSecurity http) throws Exception {

		final PasswordEncoder encoder = passwordEncoder();
		final String pass1 = encoder.encode("123");
		final String pass2 = encoder.encode("123");
		final String pass3 = encoder.encode("123");

		System.out.println("pass1: " + pass1);
		System.out.println("pass2: " + pass2);
		System.out.println("pass3: " + pass3);
		/*
			会打印：
			pass1: $2a$10$T0P/Fwx.00PRNUqFVbZL5esM2/vllxPIU7Kx3BOH6uTB6nZBneV46
			pass2: $2a$10$KjCO74QDqigRk4d5o0/MiuWSV6b1SE99CimNP274xwzwcnTvxBtqG
			pass3: $2a$10$6BAWK/7TjRW8za1ElyiCoeIVNZm4bso9iBE7znRf2gXg3O5f.1i3i
			2a是加密算法的版本号，10是重复加密的次数，盐是随机的被加在了$2a$10$之后，到哪结束不知道。
			摘要，单向加密，只做判断不做解密, 用来校验和权限相关的东西，而不是加密真正的信息。
		 */

		http.authorizeRequests().anyRequest().authenticated() // 那些地址需要登录
		.and()
		.formLogin().loginPage("/login.html")  // 登陆表单，这里对应了LoginController里的@GetMapping("/login.html")
				.loginProcessingUrl("/login")
				.permitAll()
				.failureForwardUrl("/error.html") // 登陆失败页面
				.defaultSuccessUrl("/login_success.html", false) // 登陆成功页面, true的时候：只要登陆成功，都会给用户显示欢迎页；false（默认）的时候：如果用户在访问某个页面或资源的时候被要求登录，则登陆成功后，返回他刚刚试图访问的那个资源。这个设置不能根据权限展示页面
				.usernameParameter("aaa") // Spring Security会拿着 aaa去寻找html中name="aaa"的那个input，将其value作为username
				.passwordParameter("bbb") // Spring Security会拿着 bbb去寻找html中name="bbb"的那个input，将其value作为password, 并校验能否分别对上yml中设置的spring.security.user.name和spring.security.user.password
				.failureHandler(new AuthenticationFailureHandler() { // 可以用 .failureUrl("/error.html") 但是登录失败的原因是带不过去的，所以有时候需要这么个handler
					@Override
					public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
						exception.printStackTrace();
						//登录的时候账号或密码出错，则会抛出BadCredentialsException，可以用instanceof判断各种情况作出处理，如各种错误情况下的处理、登录次数统计
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

	// 重写完这里的账号密码配置之后,yml里的配置就被覆盖了
	// Session登录，无必要网Redis里面写，这要是写，那就说明登录用户已经非常多了，此时不应该用基于会话的形式保证用户的登录状态了。
	// 当并发量高的时候，换成JWT，整套解决方案换成无状态的，基于token的校验，这里的服务器不维持会话，客户端自己提交token上来
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		PasswordEncoder encoder = passwordEncoder();
		auth
				.inMemoryAuthentication()
				.withUser("123")
				.password(encoder.encode("123"))
				.roles("admin") // 角色必填！！
				.and()
				.withUser("321")
				.password(encoder.encode("321"))
				.roles("user");
	}

	// 上面👆的用户名和密码都是明文，密码最好加密：
	// https://mkyong.com/spring-boot/spring-security-there-is-no-passwordencoder-mapped-for-the-id-null/
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}
