package com.jwt_code_practice.global.security.filter;

import java.io.IOException;
import java.util.Map;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jwt_code_practice.global.exception.ErrorCode;
import com.jwt_code_practice.global.exception.ServiceException;
import com.jwt_code_practice.global.security.dto.LoginRequest;
import com.jwt_code_practice.global.security.jwt.JwtTokenProvider;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

/**
 * JWT 인증 필터
 * <p>
 * 이 필터는 로그인 요청을 처리하고, 인증이 성공하면 JWT 토큰을 생성하여 응답 헤더에 추가합니다.
 * </p>
 */
@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private final AuthenticationManager authenticationManager;
	private final JwtTokenProvider jwtTokenProvider;
	private final ObjectMapper objectMapper;

	public JwtAuthenticationFilter(AuthenticationManager authenticationManager, JwtTokenProvider jwtTokenProvider) {
		this.authenticationManager = authenticationManager;
		this.jwtTokenProvider = jwtTokenProvider;
		this.objectMapper = new ObjectMapper();
		// 로그인 URL 설정
		setFilterProcessesUrl("/api/v1/login");
	}

	/**
	 * 인증 시도 메서드
	 * <p>
	 * 클라이언트로부터 받은 로그인 요청을 처리하고 인증을 시도합니다.
	 * </p>
	 * 
	 * @param request HTTP 요청
	 * @param response HTTP 응답
	 * @return 인증 객체
	 * @throws AuthenticationException 인증 실패 시 발생
	 */
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
		try {
			// 요청 본문에서 로그인 정보 추출
			LoginRequest loginRequest = objectMapper.readValue(request.getInputStream(), LoginRequest.class);

			// 인증 토큰 생성
			UsernamePasswordAuthenticationToken authenticationToken = 
				new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword());

			// 인증 시도
			return authenticationManager.authenticate(authenticationToken);
		} catch (IOException e) {
			log.error("Failed to parse authentication request", e);
			throw new ServiceException(ErrorCode.AUTHENTICATION_REQUEST_PARSE_ERROR);
		}
	}

	/**
	 * 인증 성공 시 호출되는 메서드
	 * <p>
	 * 인증이 성공하면 JWT 토큰을 생성하여 응답 헤더에 추가합니다.
	 * </p>
	 * 
	 * @param request HTTP 요청
	 * @param response HTTP 응답
	 * @param chain 필터 체인
	 * @param authResult 인증 결과
	 * @throws IOException IO 예외
	 * @throws ServletException 서블릿 예외
	 */
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, 
			FilterChain chain, Authentication authResult) throws IOException, ServletException {

		// JWT 토큰 생성 및 저장
		jwtTokenProvider.saveToken(authResult, response);

		// 응답 본문에 성공 메시지 추가
		response.setContentType("application/json");
		response.setCharacterEncoding("UTF-8");
		response.getWriter().write(objectMapper.writeValueAsString(Map.of(
			"status", "success",
			"message", "로그인 성공"
		)));
	}

	/**
	 * 인증 실패 시 호출되는 메서드
	 * <p>
	 * 인증이 실패하면 오류 메시지를 응답 본문에 추가합니다.
	 * </p>
	 * 
	 * @param request HTTP 요청
	 * @param response HTTP 응답
	 * @param failed 인증 예외
	 * @throws IOException IO 예외
	 * @throws ServletException 서블릿 예외
	 */
	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException, ServletException {

		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		response.setContentType("application/json");
		response.setCharacterEncoding("UTF-8");
		response.getWriter().write(objectMapper.writeValueAsString(Map.of(
			"status", "error",
			"message", "로그인 실패: " + failed.getMessage()
		)));
	}
}
