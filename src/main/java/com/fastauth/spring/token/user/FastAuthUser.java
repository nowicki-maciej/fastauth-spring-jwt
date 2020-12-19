package com.fastauth.spring.token.user;

import java.util.List;

public interface FastAuthUser {

	Long getId();
	String getLogin();
	String getPassword();
	List<String> getAuthorities();

}
