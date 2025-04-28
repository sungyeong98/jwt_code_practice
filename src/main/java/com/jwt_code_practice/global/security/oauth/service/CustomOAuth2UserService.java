package com.jwt_code_practice.global.security.oauth.service;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.jwt_code_practice.domain.member.entity.Member;
import com.jwt_code_practice.domain.member.repository.MemberRepository;
import com.jwt_code_practice.global.security.oauth.dto.OAuthAttributes;
import com.jwt_code_practice.global.security.oauth.model.OAuth2UserInfo;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
	private final MemberRepository memberRepository;

	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = new DefaultOAuth2UserService();
		OAuth2User oAuth2User = delegate.loadUser(userRequest);

		// OAuth2 서비스 ID (google, naver, kakao 등)
		String registrationId = userRequest.getClientRegistration().getRegistrationId();
		log.info("소셜 로그인 시도 : {}", registrationId);

		// OAuth2 로그인 진행 시 키가 되는 필드 값 (PK)
		String userNameAttributeName = userRequest.getClientRegistration()
			.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();

		// OAuth2UserService를 통해 가져온 OAuth2User의 attribute
		Map<String, Object> attributes = oAuth2User.getAttributes();

		// 소셜 로그인 타입에 맞는 OAuth2UserInfo 객체 생성
		OAuth2UserInfo userInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(registrationId, attributes);

		// OAuth2UserInfo를 통해 OAuthAttributes 객체 생성
		OAuthAttributes oAuthAttributes = OAuthAttributes.of(
			registrationId, userNameAttributeName, attributes, userInfo);

		// 사용자 정보 저장
		Member member = saveIfNotExist(oAuthAttributes);

		return new DefaultOAuth2User(
			Collections.singleton(new SimpleGrantedAuthority(member.getMemberRole().name())),
			oAuthAttributes.getAttributes(),
			oAuthAttributes.getNameAttributeKey());
	}

	private Member saveIfNotExist(OAuthAttributes attributes) {
		Optional<Member> socialMember = memberRepository.findByEmail(attributes.getEmail());

		return socialMember.orElseGet(() -> memberRepository.save(attributes.toEntity()));

	}
}
