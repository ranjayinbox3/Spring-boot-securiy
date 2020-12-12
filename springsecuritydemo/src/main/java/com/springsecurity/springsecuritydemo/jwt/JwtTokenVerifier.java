package com.springsecurity.springsecuritydemo.jwt;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

public class JwtTokenVerifier extends OncePerRequestFilter {

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String authorizationHeader = request.getHeader("Authorization");
		if (authorizationHeader.isEmpty() || !authorizationHeader.startsWith("Bearer ")) {
			filterChain.doFilter(request, response);
			return;
		}
		try {
			String token = authorizationHeader.replace("Bearer", "");
			String secretKey = "secretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecret";
			Jws<Claims> claimsJws = Jwts.parser()
					.setSigningKey(Keys.hmacShaKeyFor(secretKey.getBytes()))
					.parseClaimsJws(token);
			Claims claimsBody = claimsJws.getBody();
			String username = claimsBody.getSubject();
			List<Map<String, String>> authorities = (List<Map<String, String>>)claimsBody.get("authorities");
			Set<SimpleGrantedAuthority> setAuthorities = new HashSet<SimpleGrantedAuthority>();
			for (Map<String, String> map : authorities) {
				SimpleGrantedAuthority simpleGrantedAuthorities = new SimpleGrantedAuthority(map.get("authority"));
				setAuthorities.add(simpleGrantedAuthorities);
			}
			Authentication authentication = new UsernamePasswordAuthenticationToken(username, null,setAuthorities);
			SecurityContextHolder.getContext().setAuthentication(authentication);
			
		} catch (Exception e) {
			// TODO: handle exception
		}
		filterChain.doFilter(request, response);
	}

}
