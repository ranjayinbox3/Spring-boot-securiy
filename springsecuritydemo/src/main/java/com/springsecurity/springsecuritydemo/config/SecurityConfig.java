package com.springsecurity.springsecuritydemo.config;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import com.springsecurity.springsecuritydemo.Utils.ApplicationUserPermission;
import com.springsecurity.springsecuritydemo.Utils.ApplicationUserRole;
@Configuration
@EnableWebSecurity
//@EnableGlobalMethodSecurity(prePostEnabled = true)//annotation for permission based authorities
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
//	@Autowired
//	private DataSource dataSource;
	@Autowired
	private PasswordEncoder passwordEncoder;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
		.csrf().disable()
		.authorizeRequests().antMatchers("/","index","/css/*","/js/*").permitAll()
		.antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name())
		.antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
		.antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
		.antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ApplicationUserRole.ADMINTRAINEE.name(),
				ApplicationUserRole.ADMIN.name())
		.anyRequest().authenticated().and().httpBasic();
    }

	@Override
	@Bean
	protected UserDetailsService userDetailsService() {
		UserDetails userranjay = User.builder().username("userranjay")
				.password(passwordEncoder.encode("passranjay"))
				//.roles(ApplicationUserRole.STUDENT.name())
				.authorities(ApplicationUserRole.STUDENT.getGrantedAuthorities())
				.build();
		
		UserDetails adminranjay = User.builder().username("adminranjay")
				.password(passwordEncoder.encode("passranjay"))
				//.roles(ApplicationUserRole.ADMIN.name())
				.authorities(ApplicationUserRole.ADMIN.getGrantedAuthorities())
				.build();
		
		UserDetails admintraineeranjay = User.builder().username("admintraineeranjay")
				.password(passwordEncoder.encode("passranjay"))
				//.roles(ApplicationUserRole.ADMINTRAINEE.name())
				.authorities(ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities())
				.build();
		
		return new InMemoryUserDetailsManager(userranjay,adminranjay,admintraineeranjay);
	}
	
	
	
	
//	@Autowired
//	public void configAuthentication(AuthenticationManagerBuilder auth) throws Exception {
//		auth.inMemoryAuthentication().withUser("ranjay").password(("{noop}ranjay")).roles("USER");
//	}
//	
//	@Bean
//	public JdbcUserDetailsManager jdbcUserDetailsManager() throws Exception {
//		JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager();
//		jdbcUserDetailsManager.setDataSource(dataSource);
//		return jdbcUserDetailsManager;
//	}
}
