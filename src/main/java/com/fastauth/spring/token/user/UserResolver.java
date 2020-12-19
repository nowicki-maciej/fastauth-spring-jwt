package com.fastauth.spring.token.user;

import java.util.Optional;

public interface UserResolver {

	Optional<? extends FastAuthUser> findUserByUsername(String username);

}
