package com.fastauth.spring.token;

import com.fastauth.spring.token.api.FastAuthTokenService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;

@Configuration
class FastAuthServicesConfig {

	@Bean
	@ConditionalOnMissingBean
	public FastAuthTokenService tokenAuthService(
			@Value("${fastauth.token.secret}") String tokenSecret,
			@Value("${fastauth.token.expirationTime}") Long tokenExpirationTime) {
		return new DefaultFastAuthTokenService(tokenSecret, tokenExpirationTime);
	}

	@Bean
	@ConditionalOnMissingBean
	public FastAuthAuthenticationService fastAuthService(FastAuthTokenService fastAuthTokenService, AuthenticationManager authenticationManager) {
		return new DefaultFastAuthAuthenticationService(fastAuthTokenService, authenticationManager);
	}

	@Bean
	@ConditionalOnMissingBean
	public FastAuthLoginController fastAuthController(
			FastAuthAuthenticationService fastAuthAuthenticationService) {
		return new FastAuthLoginController(fastAuthAuthenticationService);
	}

}
