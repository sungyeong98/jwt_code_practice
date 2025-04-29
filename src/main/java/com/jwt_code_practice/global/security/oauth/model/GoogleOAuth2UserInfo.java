package com.jwt_code_practice.global.security.oauth.model;

import java.util.Map;

/**
 * Google OAuth2 인증으로부터 받은 사용자 정보를 처리하는 클래스입니다.
 * <p>
 * 이 클래스는 {@link OAuth2UserInfo} 인터페이스를 구현하여 Google 로그인으로부터 받은
 * 사용자 정보를 표준화된 방식으로 제공합니다. Google OAuth2 API의 응답 구조에 맞게
 * 사용자 정보를 추출하고 변환하는 역할을 담당합니다.
 * </p>
 * <p>
 * Google OAuth2 응답의 주요 특징:
 * <ul>
 *   <li>사용자 ID는 "sub" 필드에 문자열 값으로 제공됨</li>
 *   <li>사용자 이메일은 "email" 필드에 직접 제공됨</li>
 *   <li>사용자 이름은 "name" 필드에 직접 제공됨</li>
 *   <li>이메일 인증 여부는 "email_verified" 필드에 boolean 값으로 제공됨</li>
 *   <li>프로필 이미지 URL은 "picture" 필드에 제공됨</li>
 * </ul>
 * </p>
 * <p>
 * 이 클래스는 다음 컴포넌트들과 협력하여 동작합니다:
 * <ul>
 *   <li>{@link com.jwt_code_practice.global.security.oauth.service.OAuth2UserInfoFactory}: 제공자에 맞는 구현체 생성</li>
 *   <li>{@link com.jwt_code_practice.global.security.oauth.dto.OAuthAttributes}: 사용자 정보 DTO 생성</li>
 *   <li>{@link com.jwt_code_practice.global.security.oauth.service.CustomOAuth2UserService}: OAuth2 로그인 처리</li>
 * </ul>
 * </p>
 * <p>
 * 일반적인 Google OAuth2 응답 구조 예시:
 * <pre>
 * {
 *   "sub": "123456789012345678901",
 *   "name": "홍길동",
 *   "given_name": "길동",
 *   "family_name": "홍",
 *   "picture": "https://lh3.googleusercontent.com/a/ACg8ocLXYZ...",
 *   "email": "user@example.com",
 *   "email_verified": true,
 *   "locale": "ko"
 * }
 * </pre>
 * </p>
 *
 * @author sungyeong98
 * @see OAuth2UserInfo
 * @see com.jwt_code_practice.global.security.oauth.service.OAuth2UserInfoFactory
 * @see <a href="https://developers.google.com/identity/protocols/oauth2/openid-connect">Google OpenID Connect</a>
 */
public class GoogleOAuth2UserInfo implements OAuth2UserInfo{
	private final Map<String, Object> attributes;

	public GoogleOAuth2UserInfo(Map<String, Object> attributes) {
		this.attributes = attributes;
	}

	@Override
	public String getProviderId() {
		return (String) attributes.get("sub");
	}

	@Override
	public String getProvider() {
		return "google";
	}

	@Override
	public String getEmail() {
		return (String) attributes.get("email");
	}

	@Override
	public String getName() {
		return (String) attributes.get("name");
	}

	@Override
	public Map<String, Object> getAttributes() {
		return attributes;
	}
}
