package com.fastauth.spring.token;

import com.fastauth.spring.token.api.FastAuthTokenService;
import com.fastauth.spring.token.resolver.CurrentUserIdResolver;
import com.fastauth.spring.token.user.FastAuthUserDetailsService;
import com.fastauth.spring.token.user.UserResolver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
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
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Import(FastAuthServicesConfig.class)
public abstract class FastAuthConfig extends WebSecurityConfigurerAdapter implements WebMvcConfigurer {

	@Autowired
	private FastAuthTokenService fastAuthTokenService;

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(fastAuthUserDetailsService())
				.passwordEncoder(passwordEncoder());
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

	@Override
	public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
		resolvers.add(new CurrentUserIdResolver());
	}

	@Bean(BeanIds.AUTHENTICATION_MANAGER)
	@Override
	public AuthenticationManager authenticationManager() throws Exception {
		return super.authenticationManager();
	}

	@Bean
	@ConditionalOnMissingBean
	FastAuthUserDetailsService fastAuthUserDetailsService() {
		return new FastAuthUserDetailsService(userResolver());
	}

	@Bean
	@ConditionalOnMissingBean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	protected abstract void requestConfiguration(HttpSecurity http) throws Exception;

	@Bean
	protected abstract UserResolver userResolver();

	private static class UnauthorizedHandler implements AuthenticationEntryPoint {

		@Override
		public void commence(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException {
			httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, e.getMessage());
		}

	}
}
