package com.fastauth.spring.token.resolver;

import org.springframework.core.MethodParameter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

class CurrentUserIdResolver implements HandlerMethodArgumentResolver {

	@Override
	public boolean supportsParameter(MethodParameter methodParameter) {
		return methodParameter.getParameterAnnotation(TokenPrincipal.class) != null;
	}

	@Override
	public Object resolveArgument(
			MethodParameter methodParameter,
			ModelAndViewContainer modelAndViewContainer,
			NativeWebRequest nativeWebRequest,
			WebDataBinderFactory webDataBinderFactory) {

		return SecurityContextHolder
				.getContext()
				.getAuthentication()
				.getPrincipal();
	}
}
