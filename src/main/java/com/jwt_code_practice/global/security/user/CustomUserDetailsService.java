package com.jwt_code_practice.global.security.user;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.jwt_code_practice.domain.member.entity.Member;
import com.jwt_code_practice.domain.member.repository.MemberRepository;
import com.jwt_code_practice.global.security.user.dto.MemberInfo;

import lombok.RequiredArgsConstructor;

/**
 * Spring Security 인증을 위한 사용자 정보를 로드하는 서비스 클래스입니다.
 * <p>
 * 이 클래스는 {@link UserDetailsService} 인터페이스를 구현하여 Spring Security의 인증 과정에서
 * 사용자 정보를 데이터베이스에서 조회하고, {@link CustomUserDetails} 객체로 변환하는 역할을 합니다.
 * </p>
 * <p>
 * 주요 기능:
 * <ul>
 *   <li>사용자 이메일을 기반으로 데이터베이스에서 사용자 정보 조회</li>
 *   <li>조회된 사용자 정보를 Spring Security에서 사용할 수 있는 {@link UserDetails} 객체로 변환</li>
 *   <li>사용자가 존재하지 않을 경우 {@link UsernameNotFoundException} 발생</li>
 * </ul>
 * </p>
 *
 * @author sungyeong98
 * @see UserDetailsService
 * @see CustomUserDetails
 * @see MemberInfo
 */
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
	private final MemberRepository memberRepository;

	/**
	 * 사용자 이메일을 기반으로 사용자 정보를 로드합니다.
	 * <p>
	 * 이 메서드는 Spring Security의 인증 과정에서 호출되며, 사용자가 로그인 시 입력한 이메일(username)을
	 * 기반으로 데이터베이스에서 사용자 정보를 조회합니다. 조회된 사용자 정보는 {@link MemberInfo} DTO로 변환된 후,
	 * {@link CustomUserDetails} 객체로 생성되어 반환됩니다.
	 * </p>
	 * <p>
	 * 사용자가 존재하지 않을 경우, {@link UsernameNotFoundException}이 발생하며 이는 Spring Security에 의해
	 * 인증 실패로 처리됩니다. 비밀번호 검증은 이 메서드에서 수행되지 않으며, Spring Security의
	 * {@link org.springframework.security.authentication.AuthenticationProvider}에 의해 별도로 처리됩니다.
	 * </p>
	 *
	 * @param username 사용자 이메일 (로그인 시 입력한 아이디)
	 * @return 로드된 사용자 정보를 담고 있는 {@link UserDetails} 객체
	 * @throws UsernameNotFoundException 사용자를 찾을 수 없을 경우 발생
	 */
	@Override
	@Transactional(readOnly = true)
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Member member = memberRepository.findByEmail(username)
				.orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다: " + username));

		MemberInfo memberInfo = MemberInfo.from(member);
		return new CustomUserDetails(memberInfo);
	}
}
