package com.jwt_code_practice.global.security.user;

import java.io.Serial;
import java.util.Collection;
import java.util.Collections;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.jwt_code_practice.domain.member.entity.MemberStatus;
import com.jwt_code_practice.global.security.user.dto.MemberInfo;

import lombok.Getter;

/**
 * Spring Security에서 인증된 사용자 정보를 나타내는 클래스입니다.
 * <p>
 * 이 클래스는 {@link UserDetails} 인터페이스를 구현하여 Spring Security의 인증 및 권한 부여 프레임워크에서
 * 사용자 정보를 표현합니다. {@link MemberInfo}를 내부적으로 포함하여 사용자의 상세 정보에 접근합니다.
 * </p>
 * <p>
 * 주요 기능:
 * <ul>
 *   <li>사용자 인증 정보(이메일, 비밀번호) 제공</li>
 *   <li>사용자 권한 정보 제공</li>
 *   <li>계정 상태 확인(잠금, 만료, 활성화 등)</li>
 * </ul>
 * </p>
 *
 * @author sungyeong98
 * @see UserDetails
 * @see MemberInfo
 */
@Getter
public class CustomUserDetails implements UserDetails {
	@Serial
	private static final long serialVersionUID = 1L;

	private final MemberInfo memberInfo;

	public CustomUserDetails(MemberInfo info) {
		this.memberInfo = info;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return Collections.singletonList(new SimpleGrantedAuthority(memberInfo.getRole().name()));
	}

	@Override
	public String getPassword() {
		return memberInfo.getPassword();
	}

	@Override
	public String getUsername() {
		return memberInfo.getEmail();
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return !MemberStatus.BLOCKED.equals(memberInfo.getStatus());
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return MemberStatus.ACTIVE.equals(memberInfo.getStatus());
	}
}
