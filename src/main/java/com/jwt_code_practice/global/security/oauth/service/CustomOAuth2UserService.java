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

/**
 * OAuth2 인증 과정에서 사용자 정보를 로드하고 처리하는 서비스 클래스입니다.
 * <p>
 * 이 클래스는 Spring Security의 OAuth2 인증 프로세스에서 사용자 정보를 로드하고,
 * 애플리케이션의 사용자 모델로 변환하는 역할을 담당합니다. 소셜 로그인(Google, Kakao 등)을 통해
 * 인증된 사용자 정보를 처리하고, 필요한 경우 회원 가입을 자동으로 수행합니다.
 * </p>
 * <p>
 * 주요 기능:
 * <ul>
 *   <li>OAuth2 제공자로부터 사용자 정보 로드</li>
 *   <li>제공자별 사용자 정보 추출 및 표준화</li>
 *   <li>사용자 정보를 기반으로 회원 조회 또는 생성</li>
 *   <li>Spring Security에서 사용할 OAuth2User 객체 생성</li>
 * </ul>
 * </p>
 * <p>
 * OAuth2 인증 흐름:
 * <ol>
 *   <li>사용자가 소셜 로그인 버튼 클릭</li>
 *   <li>OAuth2 제공자의 로그인 페이지로 리다이렉트</li>
 *   <li>사용자가 제공자에서 인증 완료</li>
 *   <li>제공자가 인증 코드와 함께 애플리케이션으로 리다이렉트</li>
 *   <li>Spring Security의 OAuth2 클라이언트가 인증 코드로 액세스 토큰 요청</li>
 *   <li>액세스 토큰으로 사용자 정보 요청</li>
 *   <li>이 서비스의 {@link #loadUser} 메소드가 호출되어 사용자 정보 처리</li>
 *   <li>사용자 정보를 기반으로 회원 조회 또는 생성</li>
 *   <li>인증 완료 및 {@link com.jwt_code_practice.global.security.oauth.handler.OAuth2LoginSuccessHandler} 호출</li>
 * </ol>
 * </p>
 * <p>
 * 이 클래스는 다음 컴포넌트들과 협력하여 동작합니다:
 * <ul>
 *   <li>{@link OAuth2UserInfoFactory}: 제공자별 사용자 정보 추출 객체 생성</li>
 *   <li>{@link OAuthAttributes}: 제공자별 사용자 정보를 표준화된 형태로 변환</li>
 *   <li>{@link MemberRepository}: 사용자 정보 조회 및 저장</li>
 *   <li>{@link DefaultOAuth2UserService}: 기본 OAuth2 사용자 정보 로드</li>
 * </ul>
 * </p>
 *
 * @author sungyeong98
 * @see OAuth2UserService
 * @see OAuth2UserInfoFactory
 * @see OAuthAttributes
 * @see com.jwt_code_practice.global.security.oauth.handler.OAuth2LoginSuccessHandler
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
	private final MemberRepository memberRepository;

	/**
	 * OAuth2 인증 요청으로부터 사용자 정보를 로드합니다.
	 * <p>
	 * 이 메소드는 Spring Security의 OAuth2 인증 프로세스에서 자동으로 호출되며,
	 * OAuth2 제공자로부터 받은 사용자 정보를 처리하고, 애플리케이션에서 사용할
	 * {@link OAuth2User} 객체를 생성하여 반환합니다.
	 * </p>
	 * <p>
	 * 처리 과정:
	 * <ol>
	 *   <li>{@link DefaultOAuth2UserService}를 사용하여 기본 OAuth2 사용자 정보 로드</li>
	 *   <li>OAuth2 제공자 ID(registrationId) 추출</li>
	 *   <li>사용자 식별을 위한 속성 이름(userNameAttributeName) 추출</li>
	 *   <li>OAuth2 사용자 속성(attributes) 추출</li>
	 *   <li>{@link OAuth2UserInfoFactory}를 통해 제공자별 사용자 정보 추출 객체 생성</li>
	 *   <li>{@link OAuthAttributes#of} 메소드를 통해 표준화된 사용자 정보 객체 생성</li>
	 *   <li>{@link #saveIfNotExist} 메소드를 통해 사용자 정보 저장 또는 조회</li>
	 *   <li>Spring Security에서 사용할 {@link DefaultOAuth2User} 객체 생성 및 반환</li>
	 * </ol>
	 * </p>
	 * <p>
	 * 이 메소드는 다음과 같은 경우에 호출됩니다:
	 * <ul>
	 *   <li>사용자가 소셜 로그인 버튼을 클릭하고 제공자에서 인증을 완료한 후</li>
	 *   <li>제공자가 인증 코드와 함께 애플리케이션으로 리다이렉트한 후</li>
	 *   <li>Spring Security의 OAuth2 클라이언트가 인증 코드로 액세스 토큰을 요청한 후</li>
	 *   <li>액세스 토큰으로 사용자 정보를 요청한 후</li>
	 * </ul>
	 * </p>
	 * <p>
	 * 반환되는 {@link DefaultOAuth2User} 객체는 다음 정보를 포함합니다:
	 * <ul>
	 *   <li>권한 정보: 사용자의 역할(ROLE_USER 등)을 나타내는 {@link SimpleGrantedAuthority} 객체</li>
	 *   <li>속성 정보: OAuth2 제공자로부터 받은 원본 사용자 속성 맵</li>
	 *   <li>이름 속성 키: 사용자를 식별하는 데 사용되는 속성의 이름</li>
	 * </ul>
	 * </p>
	 *
	 * @param userRequest OAuth2 인증 요청 정보를 포함하는 객체
	 * @return 로드된 사용자 정보를 포함하는 OAuth2User 객체
	 * @throws OAuth2AuthenticationException OAuth2 인증 과정에서 오류 발생 시
	 * @see OAuth2UserService#loadUser
	 * @see DefaultOAuth2UserService
	 * @see OAuth2UserInfoFactory
	 * @see OAuthAttributes
	 */
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

	/**
	 * 사용자 정보가 존재하지 않는 경우 저장하고, 존재하는 경우 조회합니다.
	 * <p>
	 * 이 메소드는 소셜 로그인으로 얻은 사용자 정보를 기반으로 데이터베이스에서
	 * 기존 회원인지 확인하고, 신규 회원인 경우 회원 정보를 저장하는 역할을 담당합니다.
	 * </p>
	 * <p>
	 * 처리 과정:
	 * <ol>
	 *   <li>{@link OAuthAttributes#getEmail}로 얻은 이메일을 기반으로 회원 조회</li>
	 *   <li>회원이 존재하는 경우 해당 회원 정보 반환</li>
	 *   <li>회원이 존재하지 않는 경우 {@link OAuthAttributes#toEntity} 메소드를 통해 회원 엔티티 생성</li>
	 *   <li>생성된 회원 엔티티를 데이터베이스에 저장하고 반환</li>
	 * </ol>
	 * </p>
	 * <p>
	 * 이 메소드는 {@link #loadUser} 메소드에서 호출되어 소셜 로그인 사용자의
	 * 회원 정보를 관리하는 데 사용됩니다.
	 * </p>
	 * <p>
	 * 신규 회원으로 저장되는 경우, {@link OAuthAttributes#toEntity} 메소드에 의해
	 * 다음과 같은 기본 정보가 설정됩니다:
	 * <ul>
	 *   <li>이름: OAuth2 제공자로부터 받은 이름</li>
	 *   <li>이메일: OAuth2 제공자로부터 받은 이메일</li>
	 *   <li>비밀번호: 랜덤 UUID (소셜 로그인 사용자는 비밀번호 사용 안 함)</li>
	 *   <li>전화번호: 빈 문자열 (추후 사용자가 설정 가능)</li>
	 *   <li>회원 역할: 기본 사용자 역할(ROLE_USER)</li>
	 *   <li>회원 상태: 활성(ACTIVE)</li>
	 *   <li>회원 ID: OAuth2 제공자의 사용자 ID</li>
	 * </ul>
	 * </p>
	 *
	 * @param attributes 소셜 로그인으로 얻은 사용자 정보
	 * @return 조회되거나 저장된 회원 엔티티
	 * @see OAuthAttributes
	 * @see MemberRepository
	 * @see Member
	 */
	private Member saveIfNotExist(OAuthAttributes attributes) {
		Optional<Member> socialMember = memberRepository.findByEmail(attributes.getEmail());

		return socialMember.orElseGet(() -> memberRepository.save(attributes.toEntity()));

	}
}
