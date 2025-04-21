package com.jwt_code_practice.global.security;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.http.HttpMethod;

/**
 * 전체 허용 URL 목록을 저장, 가져오는 클래스
 * @author sungyeong98
 */
public class SecurityConstants {
	private SecurityConstants() {
		throw new IllegalStateException("Utility class");
	}

	/**
	 * 전체 허용 URL 목록
	 */
	private static final Map<HttpMethod, List<String>> PUBLIC_URLS = new HashMap<>();
	static {
		PUBLIC_URLS.put(HttpMethod.GET, Arrays.asList(
			"/h2-console/**",
			"login/oauth2/code/kakao",
			"/oauth2/authorization/kakao"
		));
	}

	/**
	 * 전체 허용 URL 목록을 반환하는 메서드
	 * @return {@link Map} 전체 허용 URL
	 */
	public static Map<HttpMethod, List<String>> getPublicUrls() {
		return PUBLIC_URLS;
	}
}
