package com.jwt_code_practice.global.security.jwt;

import java.util.Objects;

import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

/**
 * HTTP 쿠키 관련 기능을 제공하는 서비스 클래스입니다.
 * <p>
 * 이 클래스는 JWT 토큰을 HTTP 쿠키로 관리하는 기능을 담당합니다.
 * 보안 설정이 적용된 쿠키를 생성하고 삭제하는 메소드를 제공하여
 * 클라이언트와 서버 간의 안전한 토큰 교환을 지원합니다.
 * </p>
 * <p>
 * 주요 특징:
 * <ul>
 *   <li>HttpOnly 속성을 통한 JavaScript 접근 방지</li>
 *   <li>Secure 속성을 통한 HTTPS 전송 강제</li>
 *   <li>SameSite 속성을 통한 CSRF 공격 방지</li>
 *   <li>적절한 만료 시간 설정</li>
 * </ul>
 * </p>
 *
 * @author sungyeong98
 */
@Component
@RequiredArgsConstructor
public class CookieService {
	private final TokenUtilService tokenUtilService;

	/**
	 * 보안 설정이 적용된 HTTP 쿠키를 생성합니다.
	 * <p>
	 * 생성된 쿠키에는 다음과 같은 보안 설정이 적용됩니다:
	 * <ul>
	 *   <li>path="/" - 전체 도메인에서 쿠키 접근 가능</li>
	 *   <li>sameSite="None" - 크로스 사이트 요청 시에도 쿠키 전송 허용 (CORS 환경 지원)</li>
	 *   <li>secure=true - HTTPS 연결에서만 쿠키 전송</li>
	 *   <li>httpOnly=true - JavaScript에서 쿠키 접근 불가 (XSS 공격 방지)</li>
	 *   <li>maxAge - JWT 액세스 토큰의 유효 기간과 동일하게 설정 (초 단위로 변환)</li>
	 * </ul>
	 * </p>
	 * <p>
	 * 이 메소드는 주로 로그인 성공 시 JWT 토큰을 쿠키에 저장하는 용도로 사용됩니다.
	 * </p>
	 *
	 * @param key 쿠키의 이름 (예: "_at" for access token)
	 * @param value 쿠키의 값 (JWT 토큰 문자열)
	 * @return HTTP 응답 헤더에 설정할 수 있는 Set-Cookie 문자열
	 */
	public String setCookie(String key, String value) {
		return ResponseCookie.from(key, value)
			.path("/")
			.sameSite("None")
			.secure(true)
			.maxAge(tokenUtilService.getAccessTokenValidExpiration() / 1000)
			.httpOnly(true)
			.build()
			.toString();
	}

	/**
	 * 기존 HTTP 쿠키를 삭제하기 위한 만료된 쿠키를 생성합니다.
	 * <p>
	 * 쿠키 삭제는 실제로 클라이언트에 저장된 쿠키를 직접 삭제하는 것이 아니라,
	 * 동일한 이름의 쿠키를 maxAge=0으로 설정하여 브라우저가 기존 쿠키를 즉시 만료시키도록 합니다.
	 * </p>
	 * <p>
	 * 생성된 쿠키에는 다음과 같은 설정이 적용됩니다:
	 * <ul>
	 *   <li>path="/" - 원본 쿠키와 동일한 경로 설정</li>
	 *   <li>sameSite="None" - 원본 쿠키와 동일한 SameSite 설정</li>
	 *   <li>secure=true - 원본 쿠키와 동일한 Secure 설정</li>
	 *   <li>httpOnly=true - 원본 쿠키와 동일한 HttpOnly 설정</li>
	 *   <li>maxAge=0 - 쿠키를 즉시 만료시키기 위한 설정</li>
	 * </ul>
	 * </p>
	 * <p>
	 * 이 메소드는 주로 로그아웃 시 JWT 토큰 쿠키를 삭제하는 용도로 사용됩니다.
	 * </p>
	 *
	 * @param key 삭제할 쿠키의 이름 (예: "_at" for access token)
	 * @param value 삭제할 쿠키의 값 (로깅 목적으로 포함될 수 있음)
	 * @return HTTP 응답 헤더에 설정할 수 있는 Set-Cookie 문자열
	 */
	public String deleteCookie(String key, String value) {
		return ResponseCookie.from(key, value)
			.path("/")
			.sameSite("None")
			.secure(true)
			.maxAge(0)
			.httpOnly(true)
			.build()
			.toString();
	}

	public String extractToken(HttpServletRequest request) {
		if (Objects.isNull(request.getCookies())) {
			return null;
		}
		String accessToken = null;

		for (Cookie cookie : request.getCookies()) {
			if (Objects.equals(cookie.getName(), "_at")) {
				accessToken = cookie.getValue();
				break;
			}
		}

		return accessToken;
	}
}
