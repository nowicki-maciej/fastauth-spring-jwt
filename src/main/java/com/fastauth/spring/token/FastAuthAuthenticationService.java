package com.fastauth.spring.token;

import com.fastauth.spring.token.api.FastAuthToken;

public interface FastAuthAuthenticationService {

	FastAuthToken authenticate(String login, String password);

}
