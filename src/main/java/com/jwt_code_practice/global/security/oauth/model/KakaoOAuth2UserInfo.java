package com.jwt_code_practice.global.security.oauth.model;

import java.util.Map;

/**
 * Kakao OAuth2 인증으로부터 받은 사용자 정보를 처리하는 클래스입니다.
 * <p>
 * 이 클래스는 {@link OAuth2UserInfo} 인터페이스를 구현하여 Kakao 로그인으로부터 받은
 * 사용자 정보를 표준화된 방식으로 제공합니다. Kakao API의 응답 구조에 맞게
 * 사용자 정보를 추출하고 변환하는 역할을 담당합니다.
 * </p>
 * <p>
 * Kakao OAuth2 응답의 주요 특징:
 * <ul>
 *   <li>사용자 ID는 "id" 필드에 숫자 값으로 제공됨</li>
 *   <li>사용자 프로필 정보는 "kakao_account" 객체 내에 포함됨</li>
 *   <li>이메일은 "kakao_account" 객체 내의 "email" 필드에 있으나, 사용자가 이메일 제공을 거부할 수 있음</li>
 *   <li>닉네임은 "kakao_account" 객체 내의 "nickname" 필드에 제공됨</li>
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
 * 일반적인 Kakao OAuth2 응답 구조 예시:
 * <pre>
 * {
 *   "id": 123456789,
 *   "connected_at": "2023-01-01T12:34:56Z",
 *   "kakao_account": {
 *     "profile_needs_agreement": false,
 *     "profile": {
 *       "nickname": "사용자닉네임",
 *       "thumbnail_image_url": "http://k.kakaocdn.net/...",
 *       "profile_image_url": "http://k.kakaocdn.net/...",
 *       "is_default_image": false
 *     },
 *     "email_needs_agreement": false,
 *     "email": "user@example.com",
 *     "age_range_needs_agreement": true,
 *     "birthday_needs_agreement": true,
 *     "gender_needs_agreement": true
 *   }
 * }
 * </pre>
 * </p>
 *
 * @author sungyeong98
 * @see OAuth2UserInfo
 * @see com.jwt_code_practice.global.security.oauth.service.OAuth2UserInfoFactory
 * @see <a href="https://developers.kakao.com/docs/latest/ko/kakaologin/rest-api#req-user-info">Kakao API 문서</a>
 */
public class KakaoOAuth2UserInfo implements OAuth2UserInfo {
	private final Map<String, Object> attributes;
	private final Map<String, Object> properties;

	@SuppressWarnings("unchecked")
	public KakaoOAuth2UserInfo(Map<String, Object> attributes) {
		this.attributes = attributes;
		this.properties = (Map<String, Object>) attributes.get("kakao_account");
	}

	@Override
	public String getProviderId() {
		return String.valueOf(attributes.get("id"));
	}

	@Override
	public String getProvider() {
		return "kakao";
	}

	@Override
	public String getEmail() {
		return getProviderId() + "@kakao.com";
	}

	@Override
	public String getName() {
		return (String) properties.get("nickname");
	}

	@Override
	public Map<String, Object> getAttributes() {
		return attributes;
	}
}
