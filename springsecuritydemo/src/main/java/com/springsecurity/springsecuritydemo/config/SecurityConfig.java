package com.springsecurity.springsecuritydemo.config;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.springsecurity.springsecuritydemo.Utils.ApplicationUserRole;
import com.springsecurity.springsecuritydemo.auth.ApplicationUserService;
import com.springsecurity.springsecuritydemo.jwt.JwtTokenVerifier;
import com.springsecurity.springsecuritydemo.jwt.JwtUsernamePasswordAuthenticationFilter;
@Configuration
@EnableWebSecurity
//@EnableGlobalMethodSecurity(prePostEnabled = true)//annotation for permission based authorities
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
//	@Autowired
//	private DataSource dataSource;
	@Autowired
	private PasswordEncoder passwordEncoder;
	@Autowired
	private ApplicationUserService applicationUserDetailsService;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
		.csrf().disable()
		.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		.and()
		.addFilter(new JwtUsernamePasswordAuthenticationFilter(authenticationManager()))
		.addFilterAfter(new JwtTokenVerifier(), JwtUsernamePasswordAuthenticationFilter.class)
		.authorizeRequests().antMatchers("/","index","/css/*","/js/*").permitAll()
		.antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name())
		.anyRequest().authenticated();
		//.antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
		//.antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
		//.antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ApplicationUserRole.ADMINTRAINEE.name(),
				//ApplicationUserRole.ADMIN.name())
		//.anyRequest().authenticated().and()
		//.formLogin().loginPage("/login").permitAll().defaultSuccessUrl("/courses")
		//.passwordParameter("password")//paramiter names must match with names with front end name
		//.usernameParameter("username").and()//if u r changing here then u must change in front end
		//.rememberMe()
		//.rememberMeParameter("remember-me")
		//.and().logout().logoutSuccessUrl("/logout") //by default log out url called with GET method we should use POST method
		//.clearAuthentication(true)					// if csrf is enable then use POST if not enable then u can use GET
		//.invalidateHttpSession(true)
		//.deleteCookies("remeber-me","JSESSIONID")
		//.logoutSuccessUrl("/login");
    }
	
	
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(daoAuthenticationProvider());
	}



	@Bean
	public DaoAuthenticationProvider daoAuthenticationProvider() {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setPasswordEncoder(passwordEncoder);
		provider.setUserDetailsService(applicationUserDetailsService);
		return provider;
	}

	/*
	 * @Override
	 * 
	 * @Bean protected UserDetailsService userDetailsService() { UserDetails
	 * userranjay = User.builder().username("userranjay")
	 * .password(passwordEncoder.encode("passranjay"))
	 * //.roles(ApplicationUserRole.STUDENT.name())
	 * .authorities(ApplicationUserRole.STUDENT.getGrantedAuthorities()) .build();
	 * 
	 * UserDetails adminranjay = User.builder().username("adminranjay")
	 * .password(passwordEncoder.encode("passranjay"))
	 * //.roles(ApplicationUserRole.ADMIN.name())
	 * .authorities(ApplicationUserRole.ADMIN.getGrantedAuthorities()) .build();
	 * 
	 * UserDetails admintraineeranjay =
	 * User.builder().username("admintraineeranjay")
	 * .password(passwordEncoder.encode("passranjay"))
	 * //.roles(ApplicationUserRole.ADMINTRAINEE.name())
	 * .authorities(ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities())
	 * .build();
	 * 
	 * return new
	 * InMemoryUserDetailsManager(userranjay,adminranjay,admintraineeranjay); }
	 */
	
	
	
	
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
