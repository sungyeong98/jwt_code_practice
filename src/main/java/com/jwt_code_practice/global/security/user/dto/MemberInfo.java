package com.jwt_code_practice.global.security.user.dto;

import com.jwt_code_practice.domain.member.entity.Member;
import com.jwt_code_practice.domain.member.entity.MemberRole;
import com.jwt_code_practice.domain.member.entity.MemberStatus;

import lombok.Builder;
import lombok.Getter;

/**
 * 사용자 정보를 전달하기 위한 DTO(Data Transfer Object) 클래스입니다.
 * <p>
 * 이 클래스는 {@link Member} 엔티티와 {@link com.jwt_code_practice.global.security.user.CustomUserDetails} 사이의
 * 데이터 전달을 담당하며, 인증 과정에서 필요한 사용자 정보를 포함합니다.
 * </p>
 * <p>
 * 주요 정보:
 * <ul>
 *   <li>id: 사용자 고유 식별자</li>
 *   <li>email: 사용자 이메일 (로그인 아이디로 사용)</li>
 *   <li>password: 사용자 비밀번호</li>
 *   <li>name: 사용자 이름</li>
 *   <li>role: 사용자 역할 ({@link MemberRole})</li>
 *   <li>status: 사용자 상태 ({@link MemberStatus})</li>
 * </ul>
 * </p>
 *
 * @author sungyeong98
 * @see Member
 * @see MemberRole
 * @see MemberStatus
 * @see com.jwt_code_practice.global.security.user.CustomUserDetails
 */
@Getter
@Builder
public class MemberInfo {
	private Long id;
	private String email;
	private String password;
	private String name;
	private MemberRole role;
	private MemberStatus status;

	/**
	 * {@link Member} 엔티티로부터 {@link MemberInfo} 객체를 생성합니다.
	 * <p>
	 * 이 정적 팩토리 메서드는 {@link Member} 엔티티의 정보를 {@link MemberInfo} DTO로 변환하여
	 * 인증 과정에서 사용할 수 있도록 합니다.
	 * </p>
	 *
	 * @param member 변환할 {@link Member} 엔티티
	 * @return 생성된 {@link MemberInfo} 객체
	 */
	public static MemberInfo from(Member member) {
		return MemberInfo.builder()
			.id(member.getId())
			.email(member.getEmail())
			.password(member.getPassword())
			.name(member.getName())
			.role(member.getMemberRole())
			.status(member.getMemberStatus())
			.build();
	}
}
