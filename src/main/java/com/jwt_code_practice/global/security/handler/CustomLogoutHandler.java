package com.jwt_code_practice.global.security.handler;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import com.jwt_code_practice.global.security.jwt.JwtTokenProvider;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * 커스텀 로그아웃 핸들러
 * <p>
 * 이 클래스는 Spring Security의 로그아웃 프로세스를 커스터마이징하기 위한 핸들러입니다.
 * {@link LogoutHandler}와 {@link LogoutSuccessHandler} 인터페이스를 모두 구현하여
 * 로그아웃 과정과 로그아웃 성공 후 처리를 모두 담당합니다.
 * </p>
 * <p>
 * 주요 기능:
 * <ul>
 *   <li>JWT 토큰 무효화 (블랙리스트에 추가)</li>
 *   <li>클라이언트의 쿠키에서 토큰 삭제</li>
 *   <li>로그아웃 성공 시 추가 작업 수행 (로깅 등)</li>
 * </ul>
 * </p>
 * <p>
 * 이 핸들러는 Spring Security 설정에서 다음과 같이 등록됩니다:
 * <pre>
 * http.logout()
 *     .addLogoutHandler(customLogoutHandler)
 *     .logoutSuccessHandler(customLogoutHandler)
 * </pre>
 * </p>
 * <p>
 * 로그아웃 요청이 처리되면 먼저 {@link #logout} 메서드가 호출되어 토큰 무효화 작업을 수행하고,
 * 그 후 {@link #onLogoutSuccess} 메서드가 호출되어 로그아웃 성공 후 처리를 수행합니다.
 * </p>
 *
 * @see LogoutHandler
 * @see LogoutSuccessHandler
 * @see JwtTokenProvider
 */
@Slf4j
@RequiredArgsConstructor
public class CustomLogoutHandler implements LogoutHandler, LogoutSuccessHandler {
	private final JwtTokenProvider jwtTokenProvider;

	/**
	 * 로그아웃 처리 메서드
	 * <p>
	 * 이 메서드는 사용자가 로그아웃 요청을 보냈을 때 호출되며,
	 * 다음과 같은 작업을 수행합니다:
	 * <ol>
	 *   <li>HTTP 요청에서 JWT 토큰 추출</li>
	 *   <li>추출된 토큰을 블랙리스트에 추가하여 무효화</li>
	 *   <li>클라이언트의 쿠키에서 토큰 삭제</li>
	 * </ol>
	 * </p>
	 * <p>
	 * 이 메서드는 Spring Security의 로그아웃 필터에 의해 자동으로 호출됩니다.
	 * 로그아웃 URL로 요청이 들어오면 Spring Security는 이 메서드를 호출하여
	 * 사용자의 인증 상태를 종료합니다.
	 * </p>
	 * <p>
	 * 토큰 무효화 및 쿠키 삭제는 {@link JwtTokenProvider#deleteToken} 메서드를 통해 수행됩니다.
	 * </p>
	 *
	 * @param request 현재 HTTP 요청 (토큰 추출에 사용)
	 * @param response 현재 HTTP 응답 (쿠키 삭제에 사용)
	 * @param authentication 현재 인증된 사용자 정보 (null일 수 있음)
	 */
	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		log.debug("로그아웃 과정 실행 중...");
		jwtTokenProvider.deleteToken(request, response);
	}

	/**
	 * 로그아웃 성공 처리 메서드
	 * <p>
	 * 이 메서드는 로그아웃 과정이 성공적으로 완료된 후 호출되며,
	 * 로그아웃 성공 후 추가적인 작업을 수행할 수 있습니다.
	 * 현재는 로그 메시지 출력만 수행하지만, 필요에 따라 다음과 같은
	 * 작업을 추가할 수 있습니다:
	 * <ul>
	 *   <li>성공 메시지를 응답 본문에 추가</li>
	 *   <li>특정 URL로 리다이렉트</li>
	 *   <li>로그아웃 이벤트 발행</li>
	 *   <li>세션 관련 정보 정리</li>
	 * </ul>
	 * </p>
	 * <p>
	 * 이 메서드는 {@link #logout} 메서드가 성공적으로 실행된 후
	 * Spring Security의 로그아웃 필터에 의해 자동으로 호출됩니다.
	 * </p>
	 *
	 * @param request 현재 HTTP 요청
	 * @param response 현재 HTTP 응답 (성공 메시지 추가 또는 리다이렉트에 사용 가능)
	 * @param authentication 로그아웃 전 인증된 사용자 정보 (null일 수 있음)
	 */
	@Override
	public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		log.debug("로그아웃 성공!");
	}
}
