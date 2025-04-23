package com.jwt_code_practice.global.security.handler;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import com.jwt_code_practice.global.security.jwt.JwtTokenProvider;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class CustomLogoutHandler implements LogoutHandler, LogoutSuccessHandler {
	private final JwtTokenProvider jwtTokenProvider;

	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		log.debug("로그아웃 과정 실행 중...");
		jwtTokenProvider.deleteToken(request, response);
	}

	@Override
	public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		log.debug("로그아웃 성공!");
	}
}
