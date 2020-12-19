package com.fastauth.spring.token.user;

import com.fastauth.spring.token.api.FastAuthUserDetails;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.stream.Collectors;

public class FastAuthUserDetailsService implements UserDetailsService {

	private final UserResolver userResolver;

	public FastAuthUserDetailsService(UserResolver userResolver) {
		this.userResolver = userResolver;
	}

	@Override
	public UserDetails loadUserByUsername(String login) throws UsernameNotFoundException {
		FastAuthUser user = userResolver.findUserByUsername(login)
				.orElseThrow(() -> new UsernameNotFoundException("No user found with given login"));

		return new FastAuthUserDetails(
				user.getId(),
				user.getLogin(),
				user.getPassword(),
				user.getAuthorities().stream()
						.map(SimpleGrantedAuthority::new)
						.collect(Collectors.toList())
		);
	}
}
