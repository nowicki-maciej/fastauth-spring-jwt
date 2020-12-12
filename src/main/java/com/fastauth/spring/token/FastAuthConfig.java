package com.fastauth.spring.token;

import com.fastauth.spring.token.api.FastAuthTokenService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Import(FastAuthServicesConfig.class)
public abstract class FastAuthConfig extends WebSecurityConfigurerAdapter {

	private final UserDetailsService userDetailsService;
	private final FastAuthTokenService fastAuthTokenService;

	public FastAuthConfig(UserDetailsService userDetailsService, FastAuthTokenService fastAuthTokenService) {
		this.userDetailsService = userDetailsService;
		this.fastAuthTokenService = fastAuthTokenService;
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService).passwordEncoder(new BCryptPasswordEncoder());
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				.cors()
				.and()
				.csrf().disable()
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				.and()
				.exceptionHandling().authenticationEntryPoint(new UnauthorizedHandler());

		requestConfiguration(http);
		http.authorizeRequests().anyRequest().authenticated();

		http.addFilter(new FastAuthJWTAuthorizationFilter(authenticationManager(), fastAuthTokenService));
	}

	@Bean(BeanIds.AUTHENTICATION_MANAGER)
	@Override
	public AuthenticationManager authenticationManager() throws Exception {
		return super.authenticationManager();
	}

	protected abstract void requestConfiguration(HttpSecurity http) throws Exception;

	private static class UnauthorizedHandler implements AuthenticationEntryPoint {

		@Override
		public void commence(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException {
			httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, e.getMessage());
		}

	}
}
