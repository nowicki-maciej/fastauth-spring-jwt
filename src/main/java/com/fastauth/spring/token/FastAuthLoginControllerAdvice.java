package com.fastauth.spring.token;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice(assignableTypes = { FastAuthLoginController.class })
class FastAuthLoginControllerAdvice {

	@ExceptionHandler({ BadCredentialsException.class })
	public ResponseEntity<?> handleBadCredentialsException() {
		return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
	}
}
