package com.fastauth.spring.token;

import com.fastauth.spring.token.api.FastAuthToken;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;

@RestController
class FastAuthLoginController {

	private final FastAuthAuthenticationService fastAuthAuthenticationService;

	public FastAuthLoginController(FastAuthAuthenticationService fastAuthAuthenticationService) {
		this.fastAuthAuthenticationService = fastAuthAuthenticationService;
	}

	@PostMapping("${fastauth.login.url}")
	public ResponseEntity<TokenDto> login(@Valid @RequestBody LoginDto loginDto) {
		FastAuthToken token = fastAuthAuthenticationService.authenticate(loginDto.login, loginDto.password);
		return ResponseEntity.ok(new TokenDto(token.getValue()));
	}

	static class LoginDto {

		@NotBlank
		private final String login;

		@NotBlank
		private final String password;

		@JsonCreator
		public LoginDto(
				@JsonProperty("login") @NotBlank String login,
				@JsonProperty("password") @NotBlank String password) {
			this.login = login;
			this.password = password;
		}

	}

	static class TokenDto {

		private final String value;

		public TokenDto(String value) {
			this.value = value;
		}

		public String getValue() {
			return value;
		}
	}

}
