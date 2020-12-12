package com.fastauth.spring.token.api;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.List;

public class FastAuthToken {

	private final String value;
	private DecodedJWT decodedToken;

	public FastAuthToken(String value) {
		this.value = value;
	}

	public List<String> getAuthorities() {
		return getDecoded().getClaim("authorities").asList(String.class);
	}

	public String getSubject() {
		return getDecoded().getSubject();
	}

	public String getValue() {
		return value;
	}

	private DecodedJWT getDecoded() {
		if (decodedToken == null) {
			decodedToken = JWT.decode(value);
		}

		return decodedToken;
	}
}
