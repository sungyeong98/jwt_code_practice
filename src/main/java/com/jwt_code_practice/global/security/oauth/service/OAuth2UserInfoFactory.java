package com.jwt_code_practice.global.security.oauth.service;

import java.util.Map;

import com.jwt_code_practice.global.exception.ErrorCode;
import com.jwt_code_practice.global.exception.ServiceException;
import com.jwt_code_practice.global.security.oauth.model.GoogleOAuth2UserInfo;
import com.jwt_code_practice.global.security.oauth.model.KakaoOAuth2UserInfo;
import com.jwt_code_practice.global.security.oauth.model.OAuth2UserInfo;

import lombok.experimental.UtilityClass;

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
