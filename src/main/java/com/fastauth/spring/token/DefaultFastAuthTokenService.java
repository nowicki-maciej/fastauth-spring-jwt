package com.fastauth.spring.token;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fastauth.spring.token.api.FastAuthToken;
import com.fastauth.spring.token.api.FastAuthTokenService;
import com.fastauth.spring.token.api.FastAuthUserDetails;
import org.springframework.security.core.GrantedAuthority;

import java.util.Date;

class DefaultFastAuthTokenService implements FastAuthTokenService {

	private static final String CLAIM_AUTHORITIES = "authorities";

	private final Algorithm cipherAlgorithm;
	private final long tokenExpirationTime;

	public DefaultFastAuthTokenService(String tokenSecret, Long tokenExpirationTime) {
		this.cipherAlgorithm = Algorithm.HMAC512(tokenSecret.getBytes());
		this.tokenExpirationTime = tokenExpirationTime;
	}

	@Override
	public FastAuthToken issue(FastAuthUserDetails userDetails) {
		String[] authoritiesArray = userDetails.getAuthorities().stream()
				.map(GrantedAuthority::getAuthority)
				.toArray(String[]::new);

		String token = JWT.create()
				.withSubject(userDetails.getUsername())
				.withExpiresAt(new Date(System.currentTimeMillis() + tokenExpirationTime))
				.withArrayClaim(CLAIM_AUTHORITIES, authoritiesArray)
				.sign(cipherAlgorithm);

		return new FastAuthToken(token);
	}

	@Override
	public FastAuthToken validate(String token) {
		JWT.require(cipherAlgorithm)
				.build()
				.verify(token);

		return new FastAuthToken(token);
	}
}
