package com.fastauth.spring.token;

import com.fastauth.spring.token.api.FastAuthToken;
import com.fastauth.spring.token.api.FastAuthTokenService;
import com.fastauth.spring.token.api.FastAuthUserDetails;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Arrays;

import static java.util.stream.Collectors.toList;

class DefaultFastAuthAuthenticationService implements FastAuthAuthenticationService {

	private final FastAuthTokenService fastAuthTokenService;
	private final AuthenticationManager authenticationManager;

	public DefaultFastAuthAuthenticationService(FastAuthTokenService fastAuthTokenService, AuthenticationManager authenticationManager) {
		this.fastAuthTokenService = fastAuthTokenService;
		this.authenticationManager = authenticationManager;
	}

	@Override
	public FastAuthToken authenticate(String login, String password) {
		try {
			Authentication authResult = authenticationManager.authenticate(
					authentication(login, password)
			);

			FastAuthUserDetails userDetails = (FastAuthUserDetails) authResult.getPrincipal();

			return fastAuthTokenService.issue(userDetails);
		} catch (AuthenticationException e) {
			throw new BadCredentialsException("Credentials not found");
		}
	}

	private UsernamePasswordAuthenticationToken authentication(Object principal, Object credentials, String... authorities) {
		return new UsernamePasswordAuthenticationToken(
				principal,
				credentials,
				Arrays.stream(authorities)
						.map(SimpleGrantedAuthority::new)
						.collect(toList())
		);
	}

}
