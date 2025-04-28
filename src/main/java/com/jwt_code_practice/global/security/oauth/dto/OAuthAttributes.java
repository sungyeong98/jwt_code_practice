package com.jwt_code_practice.global.security.oauth.dto;

import java.util.Map;
import java.util.UUID;

import com.jwt_code_practice.domain.member.entity.Member;
import com.jwt_code_practice.domain.member.entity.MemberRole;
import com.jwt_code_practice.domain.member.entity.MemberStatus;
import com.jwt_code_practice.global.security.oauth.model.OAuth2UserInfo;

import lombok.Builder;
import lombok.Getter;

@Getter
public class OAuthAttributes {
	private final Map<String, Object> attributes;
	private final String nameAttributeKey;
	private final String name;
	private final String email;
	private final String provider;
	private final String providerId;

	@Builder
	public OAuthAttributes(Map<String, Object> attributes, String nameAttributeKey, String name, String email, String provider, String providerId) {
		this.attributes = attributes;
		this.nameAttributeKey = nameAttributeKey;
		this.name = name;
		this.email = email;
		this.provider = provider;
		this.providerId = providerId;
	}

	public static OAuthAttributes of(String registrationId, String userNameAttributeName, Map<String, Object> attributes, OAuth2UserInfo userInfo) {
		return OAuthAttributes.builder()
			.name(userInfo.getName())
			.email(userInfo.getEmail())
			.provider(registrationId)
			.providerId(userInfo.getProviderId())
			.attributes(attributes)
			.nameAttributeKey(userNameAttributeName)
			.build();
	}

	public Member toEntity() {
		return Member.builder()
			.name(name)
			.email(email)
			.password(UUID.randomUUID().toString())
			.phone("")
			.memberRole(MemberRole.ROLE_USER)
			.memberStatus(MemberStatus.ACTIVE)
			.memberId(providerId)
			.build();
	}
}
