package com.jwt_code_practice.global.security.oauth.model;

import java.util.Map;

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
