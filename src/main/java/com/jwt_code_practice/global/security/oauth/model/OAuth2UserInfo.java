package com.jwt_code_practice.global.security.oauth.model;

import java.util.Map;

public interface OAuth2UserInfo {
	String getProviderId();
	String getProvider();
	String getEmail();
	String getName();
	Map<String, Object> getAttributes();
}
