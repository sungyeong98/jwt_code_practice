package com.jwt_code_practice.global.security.oauth.dto;

import java.util.Map;
import java.util.UUID;

import com.jwt_code_practice.domain.member.entity.Member;
import com.jwt_code_practice.domain.member.entity.MemberRole;
import com.jwt_code_practice.domain.member.entity.MemberStatus;
import com.jwt_code_practice.global.security.oauth.model.OAuth2UserInfo;

import lombok.Builder;
import lombok.Getter;

/**
 * OAuth2 인증 과정에서 사용자 정보를 담는 DTO 클래스입니다.
 * <p>
 * 이 클래스는 다양한 OAuth2 제공자(Google, Kakao, Naver 등)로부터 받은
 * 사용자 정보를 표준화된 형태로 변환하여 저장하는 역할을 합니다.
 * 각 OAuth2 제공자마다 사용자 정보의 구조와 필드명이 다르기 때문에,
 * 이 클래스를 통해 일관된 방식으로 사용자 정보를 처리할 수 있습니다.
 * </p>
 * <p>
 * 주요 기능:
 * <ul>
 *   <li>OAuth2 제공자로부터 받은 원본 속성 맵 저장</li>
 *   <li>사용자 식별을 위한 주요 속성 이름 저장</li>
 *   <li>사용자 이름, 이메일 등 기본 정보 저장</li>
 *   <li>OAuth2 제공자 정보 및 제공자 내 사용자 ID 저장</li>
 *   <li>사용자 정보를 기반으로 Member 엔티티 생성</li>
 * </ul>
 * </p>
 * <p>
 * 이 클래스는 다음 컴포넌트들과 협력하여 동작합니다:
 * <ul>
 *   <li>{@link OAuth2UserInfo}: 각 OAuth2 제공자별 사용자 정보 추출 인터페이스</li>
 *   <li>{@link com.jwt_code_practice.global.security.oauth.service.CustomOAuth2UserService}: OAuth2 로그인 처리 서비스</li>
 *   <li>{@link Member}: 사용자 정보를 저장하는 엔티티</li>
 * </ul>
 * </p>
 * <p>
 * 일반적인 사용 흐름:
 * <ol>
 *   <li>OAuth2 로그인 성공 시 제공자로부터 사용자 정보 수신</li>
 *   <li>{@link OAuth2UserInfo} 구현체를 통해 제공자별 사용자 정보 추출</li>
 *   <li>{@link #of} 메소드를 통해 OAuthAttributes 객체 생성</li>
 *   <li>사용자 정보 처리 (회원가입 또는 로그인)</li>
 *   <li>필요한 경우 {@link #toEntity} 메소드를 통해 Member 엔티티 생성</li>
 * </ol>
 * </p>
 *
 * @author sungyeong98
 * @see OAuth2UserInfo
 * @see com.jwt_code_practice.global.security.oauth.service.CustomOAuth2UserService
 * @see com.jwt_code_practice.global.security.oauth.service.OAuth2UserInfoFactory
 */
@Getter
public class OAuthAttributes {
	private final Map<String, Object> attributes;
	private final String nameAttributeKey;
	private final String name;
	private final String email;
	private final String provider;
	private final String providerId;

	/**
	 * OAuthAttributes 객체를 생성하는 빌더 패턴 기반 생성자입니다.
	 * <p>
	 * 이 생성자는 {@link Builder} 어노테이션을 통해 생성된 빌더를 통해 호출되며,
	 * 모든 필드를 초기화합니다. 직접 호출하기보다는 {@link #of} 메소드나
	 * 빌더를 통해 객체를 생성하는 것이 권장됩니다.
	 * </p>
	 * <p>
	 * 예시 코드:
	 * <pre>
	 * OAuthAttributes attributes = OAuthAttributes.builder()
	 *     .name("John Doe")
	 *     .email("john.doe@example.com")
	 *     .provider("google")
	 *     .providerId("123456789")
	 *     .attributes(userAttributes)
	 *     .nameAttributeKey("sub")
	 *     .build();
	 * </pre>
	 * </p>
	 *
	 * @param attributes OAuth2 제공자로부터 받은 원본 사용자 속성 맵
	 * @param nameAttributeKey 사용자를 식별하는 데 사용되는 속성의 이름
	 * @param name 사용자의 이름
	 * @param email 사용자의 이메일 주소
	 * @param provider OAuth2 제공자의 식별자
	 * @param providerId 제공자 내에서의 사용자 고유 식별자
	 * @see Builder
	 */
	@Builder
	public OAuthAttributes(Map<String, Object> attributes, String nameAttributeKey, String name, String email, String provider, String providerId) {
		this.attributes = attributes;
		this.nameAttributeKey = nameAttributeKey;
		this.name = name;
		this.email = email;
		this.provider = provider;
		this.providerId = providerId;
	}

	/**
	 * OAuth2 제공자 정보와 사용자 속성을 기반으로 OAuthAttributes 객체를 생성합니다.
	 * <p>
	 * 이 메소드는 다양한 OAuth2 제공자로부터 받은 사용자 정보를 표준화된 OAuthAttributes 객체로
	 * 변환하는 팩토리 메소드입니다. {@link OAuth2UserInfo} 인터페이스를 통해 제공자별 특성에 맞게
	 * 사용자 정보를 추출하고, 이를 기반으로 OAuthAttributes 객체를 생성합니다.
	 * </p>
	 * <p>
	 * 이 메소드는 주로 {@link com.jwt_code_practice.global.security.oauth.service.CustomOAuth2UserService}에서
	 * OAuth2 로그인 처리 과정에서 호출됩니다.
	 * </p>
	 * <p>
	 * 예시 코드:
	 * <pre>
	 * // OAuth2UserInfoFactory를 통해 제공자별 사용자 정보 추출 객체 생성
	 * OAuth2UserInfo userInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(
	 *     registrationId, attributes);
	 *
	 * // OAuthAttributes 객체 생성
	 * OAuthAttributes oAuthAttributes = OAuthAttributes.of(
	 *     registrationId, userNameAttributeName, attributes, userInfo);
	 * </pre>
	 * </p>
	 *
	 * @param registrationId OAuth2 제공자의 등록 ID (예: "google", "kakao", "naver")
	 * @param userNameAttributeName 사용자를 식별하는 데 사용되는 속성의 이름
	 * @param attributes OAuth2 제공자로부터 받은 원본 사용자 속성 맵
	 * @param userInfo 제공자별 사용자 정보 추출을 위한 {@link OAuth2UserInfo} 객체
	 * @return 생성된 OAuthAttributes 객체
	 * @see com.jwt_code_practice.global.security.oauth.service.OAuth2UserInfoFactory
	 * @see com.jwt_code_practice.global.security.oauth.service.CustomOAuth2UserService
	 */
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

	/**
	 * OAuthAttributes 객체의 정보를 기반으로 Member 엔티티를 생성합니다.
	 * <p>
	 * 이 메소드는 OAuth2 로그인을 통해 얻은 사용자 정보를 기반으로
	 * 애플리케이션의 사용자 엔티티를 생성합니다. 주로 신규 사용자가 OAuth2 로그인을 통해
	 * 처음 접속했을 때 회원가입 처리를 위해 호출됩니다.
	 * </p>
	 * <p>
	 * 생성되는 Member 엔티티의 특징:
	 * <ul>
	 *   <li>이름과 이메일은 OAuth2 제공자로부터 받은 정보 사용</li>
	 *   <li>비밀번호는 랜덤 UUID 문자열로 설정 (소셜 로그인 사용자는 비밀번호 사용 안 함)</li>
	 *   <li>전화번호는 빈 문자열로 초기화 (추후 사용자가 설정 가능)</li>
	 *   <li>회원 역할은 기본 사용자 역할(ROLE_USER)로 설정</li>
	 *   <li>회원 상태는 활성(ACTIVE)으로 설정</li>
	 *   <li>회원 ID는 OAuth2 제공자의 사용자 ID로 설정</li>
	 * </ul>
	 * </p>
	 * <p>
	 * 이 메소드는 주로 {@link com.jwt_code_practice.global.security.oauth.service.CustomOAuth2UserService}에서
	 * 신규 사용자 등록 시 호출됩니다.
	 * </p>
	 * <p>
	 * 예시 코드:
	 * <pre>
	 * // 사용자 정보 조회
	 * Optional<Member> memberOptional = memberRepository.findByEmail(oAuthAttributes.getEmail());
	 *
	 * // 신규 사용자인 경우 회원가입 처리
	 * if (memberOptional.isEmpty()) {
	 *     Member member = oAuthAttributes.toEntity();
	 *     memberRepository.save(member);
	 *     return member;
	 * }
	 * </pre>
	 * </p>
	 *
	 * @return 생성된 Member 엔티티
	 * @see Member
	 * @see com.jwt_code_practice.global.security.oauth.service.CustomOAuth2UserService
	 */
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
