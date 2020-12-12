package com.fastauth.spring.token;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.fastauth.spring.token.api.FastAuthToken;
import com.fastauth.spring.token.api.FastAuthTokenService;
import com.fastauth.spring.token.api.FastAuthUserDetails;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Optional;

import static java.util.stream.Collectors.toList;

class FastAuthJWTAuthorizationFilter extends BasicAuthenticationFilter {

	private static final String TOKEN_PREFIX = "Bearer ";
	private static final String HEADER_STRING = "Authorization";

	private final FastAuthTokenService fastAuthTokenService;

	public FastAuthJWTAuthorizationFilter(AuthenticationManager authenticationManager, FastAuthTokenService fastAuthTokenService) {
		super(authenticationManager);
		this.fastAuthTokenService = fastAuthTokenService;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
		String header = request.getHeader(HEADER_STRING);

		if (header != null && header.startsWith(TOKEN_PREFIX)) {
			tryAuthenticate(request);
		}

		chain.doFilter(request, response);
	}

	private void tryAuthenticate(HttpServletRequest request) {
		String tokenHeaderValue = request.getHeader(HEADER_STRING);
		if (tokenHeaderValue == null) {
			return;
		}

		validateToken(tokenHeaderValue).ifPresent(token -> {
			SecurityContextHolder.getContext().setAuthentication(authFromToken(token));
		});
	}

	private Authentication authFromToken(FastAuthToken token) {
		List<SimpleGrantedAuthority> authorities = token.getAuthorities().stream()
				.map(SimpleGrantedAuthority::new)
				.collect(toList());

		return new UsernamePasswordAuthenticationToken(
				new FastAuthUserDetails(token.getSubject(), null, authorities),
				null,
				authorities
		);
	}

	private Optional<FastAuthToken> validateToken(String tokenHeaderValue) {
		try {
			FastAuthToken token = fastAuthTokenService.validate(tokenHeaderValue.replace(TOKEN_PREFIX, ""));
			return Optional.of(token);
		} catch (JWTVerificationException e) {
			return Optional.empty();
		}
	}
}
