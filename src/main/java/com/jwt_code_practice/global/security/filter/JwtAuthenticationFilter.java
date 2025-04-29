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
 * 이 필터는 Spring Security의 인증 프로세스에서 사용자 로그인 요청을 처리하고,
 * 인증이 성공하면 JWT 토큰을 생성하여 응답 헤더에 추가합니다.
 * </p>
 * <p>
 * 주요 기능:
 * <ul>
 *   <li>로그인 요청 URL(/api/v1/login)에 대한 POST 요청 처리</li>
 *   <li>요청 본문에서 이메일과 비밀번호 추출</li>
 *   <li>AuthenticationManager를 통한 사용자 인증</li>
 *   <li>인증 성공 시 JWT 토큰 생성 및 응답 헤더 설정</li>
 *   <li>인증 결과에 따른 적절한 응답 메시지 생성</li>
 * </ul>
 * </p>
 * <p>
 * 이 필터는 {@link UsernamePasswordAuthenticationFilter}를 확장하여
 * Spring Security의 표준 인증 메커니즘을 JWT 기반 인증으로 대체합니다.
 * </p>
 *
 * @see JwtTokenProvider
 * @see LoginRequest
 * @see AuthenticationManager
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
	 * 이 메서드는 다음과 같은 작업을 수행합니다:
	 * <ol>
	 *   <li>HTTP 요청 본문에서 JSON 형식의 로그인 정보를 추출하여 {@link LoginRequest} 객체로 변환</li>
	 *   <li>이메일과 비밀번호를 사용하여 {@link UsernamePasswordAuthenticationToken} 생성</li>
	 *   <li>{@link AuthenticationManager}를 통해 사용자 인증 시도</li>
	 * </ol>
	 * </p>
	 * <p>
	 * 요청 본문 파싱 중 오류가 발생하면 {@link ServiceException}을 발생시킵니다.
	 * </p>
	 *
	 * @param request HTTP 요청 객체 (로그인 정보 포함)
	 * @param response HTTP 응답 객체
	 * @return 인증 결과를 나타내는 {@link Authentication} 객체
	 * @throws AuthenticationException 인증 실패 시 발생
	 * @throws ServiceException 요청 파싱 오류 시 발생
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
	 * 인증이 성공하면 다음과 같은 작업을 수행합니다:
	 * <ol>
	 *   <li>{@link JwtTokenProvider}를 사용하여 JWT 토큰 생성</li>
	 *   <li>생성된 토큰을 HTTP 응답 쿠키에 추가</li>
	 *   <li>응답 본문에 JSON 형식의 성공 메시지 작성</li>
	 * </ol>
	 * </p>
	 * <p>
	 * 이 메서드는 Spring Security의 인증 프로세스에서 인증이 성공적으로 완료된 후 자동으로 호출됩니다.
	 * </p>
	 *
	 * @param request HTTP 요청 객체
	 * @param response HTTP 응답 객체 (토큰과 성공 메시지가 추가됨)
	 * @param chain 필터 체인 (다음 필터로 요청을 전달하는 데 사용)
	 * @param authResult 인증 성공 결과를 나타내는 {@link Authentication} 객체
	 * @throws IOException 응답 작성 중 I/O 오류 발생 시
	 * @throws ServletException 서블릿 처리 중 오류 발생 시
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
	 * 인증이 실패하면 다음과 같은 작업을 수행합니다:
	 * <ol>
	 *   <li>HTTP 응답 상태 코드를 401 (Unauthorized)로 설정</li>
	 *   <li>응답 본문에 JSON 형식의 오류 메시지 작성</li>
	 * </ol>
	 * </p>
	 * <p>
	 * 이 메서드는 다음과 같은 경우에 호출될 수 있습니다:
	 * <ul>
	 *   <li>사용자 이메일이 존재하지 않는 경우</li>
	 *   <li>비밀번호가 일치하지 않는 경우</li>
	 *   <li>계정이 잠겨 있거나 비활성화된 경우</li>
	 *   <li>기타 인증 관련 예외가 발생한 경우</li>
	 * </ul>
	 * </p>
	 * <p>
	 * 이 메서드는 Spring Security의 인증 프로세스에서 인증이 실패했을 때 자동으로 호출됩니다.
	 * </p>
	 *
	 * @param request HTTP 요청 객체
	 * @param response HTTP 응답 객체 (오류 메시지가 추가됨)
	 * @param failed 인증 실패 원인을 나타내는 {@link AuthenticationException} 객체
	 * @throws IOException 응답 작성 중 I/O 오류 발생 시
	 * @throws ServletException 서블릿 처리 중 오류 발생 시
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
