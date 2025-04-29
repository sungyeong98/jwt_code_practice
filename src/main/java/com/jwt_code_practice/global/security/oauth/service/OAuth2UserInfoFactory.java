package com.jwt_code_practice.global.security.oauth.service;

import java.util.Map;

import com.jwt_code_practice.global.exception.ErrorCode;
import com.jwt_code_practice.global.exception.ServiceException;
import com.jwt_code_practice.global.security.oauth.model.GoogleOAuth2UserInfo;
import com.jwt_code_practice.global.security.oauth.model.KakaoOAuth2UserInfo;
import com.jwt_code_practice.global.security.oauth.model.OAuth2UserInfo;

import lombok.experimental.UtilityClass;

/**
 * OAuth2 인증 제공자별 사용자 정보 추출 객체를 생성하는 팩토리 클래스입니다.
 * <p>
 * 이 클래스는 다양한 OAuth2 제공자(Google, Kakao 등)로부터 받은 사용자 정보를
 * 처리하기 위한 적절한 {@link OAuth2UserInfo} 구현체를 생성하는 팩토리 메소드를 제공합니다.
 * 팩토리 패턴을 사용하여 제공자별 구현 세부 사항을 캡슐화하고, 클라이언트 코드가
 * 일관된 인터페이스를 통해 다양한 제공자의 사용자 정보에 접근할 수 있도록 합니다.
 * </p>
 * <p>
 * 주요 특징:
 * <ul>
 *   <li>제공자 ID(registrationId)에 따라 적절한 {@link OAuth2UserInfo} 구현체 생성</li>
 *   <li>지원되지 않는 제공자에 대한 예외 처리</li>
 *   <li>정적 유틸리티 메소드를 통한 간편한 접근</li>
 * </ul>
 * </p>
 * <p>
 * 현재 지원되는 OAuth2 제공자:
 * <ul>
 *   <li>Google ("google"): {@link GoogleOAuth2UserInfo} 구현체 사용</li>
 *   <li>Kakao ("kakao"): {@link KakaoOAuth2UserInfo} 구현체 사용</li>
 * </ul>
 * </p>
 * <p>
 * 이 클래스는 다음 컴포넌트들과 협력하여 동작합니다:
 * <ul>
 *   <li>{@link OAuth2UserInfo}: 제공자별 사용자 정보 추출을 위한 공통 인터페이스</li>
 *   <li>{@link GoogleOAuth2UserInfo}: Google 로그인 사용자 정보 처리 구현체</li>
 *   <li>{@link KakaoOAuth2UserInfo}: Kakao 로그인 사용자 정보 처리 구현체</li>
 *   <li>{@link com.jwt_code_practice.global.security.oauth.service.CustomOAuth2UserService}: OAuth2 로그인 처리 서비스</li>
 *   <li>{@link com.jwt_code_practice.global.security.oauth.handler.OAuth2LoginSuccessHandler}: OAuth2 로그인 성공 처리 핸들러</li>
 * </ul>
 * </p>
 * <p>
 * 이 클래스는 {@link UtilityClass} 어노테이션이 적용되어 있어,
 * 인스턴스화를 방지하고 정적 메소드만 제공하는 유틸리티 클래스로 동작합니다.
 * </p>
 *
 * @author sungyeong98
 * @see OAuth2UserInfo
 * @see GoogleOAuth2UserInfo
 * @see KakaoOAuth2UserInfo
 * @see com.jwt_code_practice.global.security.oauth.service.CustomOAuth2UserService
 * @see com.jwt_code_practice.global.security.oauth.handler.OAuth2LoginSuccessHandler
 */
@UtilityClass
public class OAuth2UserInfoFactory {
	public static OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
		return switch (registrationId) {
			case "kakao" -> new KakaoOAuth2UserInfo(attributes);
			case "google" -> new GoogleOAuth2UserInfo(attributes);
			default -> throw new ServiceException(ErrorCode.NOT_SUPPORTED_OAUTH_LOGIN);
		};
	}
}
