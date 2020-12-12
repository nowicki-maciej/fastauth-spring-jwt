package com.fastauth.spring.token.api;

public interface FastAuthTokenService {

	FastAuthToken issue(FastAuthUserDetails userDetails);

	FastAuthToken validate(String tokenValue);

}
