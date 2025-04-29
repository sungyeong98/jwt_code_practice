package com.jwt_code_practice.global.security.oauth.model;

import java.util.Map;

/**
 * OAuth2 인증 제공자로부터 받은 사용자 정보를 표준화하는 인터페이스입니다.
 * <p>
 * 이 인터페이스는 다양한 OAuth2 제공자(Google, Kakao, Naver 등)로부터 받은
 * 사용자 정보를 일관된 방식으로 접근할 수 있도록 추상화합니다. 각 OAuth2 제공자마다
 * 사용자 정보의 구조와 필드명이 다르기 때문에, 이 인터페이스를 구현하는 클래스들은
 * 제공자별 특성에 맞게 사용자 정보를 추출하고 표준화된 메소드를 통해 제공합니다.
 * </p>
 * <p>
 * 주요 기능:
 * <ul>
 *   <li>제공자 내에서의 사용자 고유 식별자 제공</li>
 *   <li>OAuth2 제공자 정보 제공</li>
 *   <li>사용자 이메일 주소 제공</li>
 *   <li>사용자 이름 제공</li>
 *   <li>원본 속성 맵 접근 제공</li>
 * </ul>
 * </p>
 * <p>
 * 이 인터페이스는 다음과 같은 구현체들을 가질 수 있습니다:
 * <ul>
 *   <li>{@code GoogleOAuth2UserInfo}: Google 로그인 사용자 정보 처리</li>
 *   <li>{@code KakaoOAuth2UserInfo}: Kakao 로그인 사용자 정보 처리</li>
 *   <li>{@code NaverOAuth2UserInfo}: Naver 로그인 사용자 정보 처리</li>
 * </ul>
 * </p>
 * <p>
 * 이 인터페이스는 다음 컴포넌트들과 협력하여 동작합니다:
 * <ul>
 *   <li>{@link com.jwt_code_practice.global.security.oauth.service.OAuth2UserInfoFactory}: 제공자별 구현체 생성</li>
 *   <li>{@link com.jwt_code_practice.global.security.oauth.dto.OAuthAttributes}: 사용자 정보 DTO 생성</li>
 *   <li>{@link com.jwt_code_practice.global.security.oauth.service.CustomOAuth2UserService}: OAuth2 로그인 처리</li>
 * </ul>
 * </p>
 * <p>
 * 일반적인 사용 흐름:
 * <ol>
 *   <li>OAuth2 로그인 성공 시 제공자로부터 사용자 정보 수신</li>
 *   <li>{@code OAuth2UserInfoFactory}를 통해 제공자에 맞는 구현체 생성</li>
 *   <li>구현체의 메소드를 통해 표준화된 사용자 정보 접근</li>
 *   <li>사용자 정보를 기반으로 회원가입 또는 로그인 처리</li>
 * </ol>
 * </p>
 * <p>
 * 예시 코드:
 * <pre>
 * // OAuth2 인증 결과에서 제공자 ID와 속성 맵 추출
 * String registrationId = ((OAuth2AuthenticationToken) authentication).getAuthorizedClientRegistrationId();
 * Map&lt;String, Object&gt; attributes = ((OAuth2User) authentication.getPrincipal()).getAttributes();
 *
 * // 제공자에 맞는 OAuth2UserInfo 구현체 생성
 * OAuth2UserInfo userInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(registrationId, attributes);
 *
 * // 표준화된 메소드로 사용자 정보 접근
 * String email = userInfo.getEmail();
 * String name = userInfo.getName();
 * String providerId = userInfo.getProviderId();
 * </pre>
 * </p>
 *
 * @author sungyeong98
 * @see com.jwt_code_practice.global.security.oauth.service.OAuth2UserInfoFactory
 * @see com.jwt_code_practice.global.security.oauth.dto.OAuthAttributes
 * @see com.jwt_code_practice.global.security.oauth.service.CustomOAuth2UserService
 */
public interface OAuth2UserInfo {
	String getProviderId();
	String getProvider();
	String getEmail();
	String getName();
	Map<String, Object> getAttributes();
}
