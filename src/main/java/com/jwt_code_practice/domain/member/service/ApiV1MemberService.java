package com.jwt_code_practice.domain.member.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.jwt_code_practice.domain.member.dto.request.SignupRequest;
import com.jwt_code_practice.domain.member.entity.Member;
import com.jwt_code_practice.domain.member.repository.MemberRepository;
import com.jwt_code_practice.global.exception.ErrorCode;
import com.jwt_code_practice.global.exception.ServiceException;

import lombok.RequiredArgsConstructor;

/**
 * 사용자 서비스 구현체 클래스
 * @author sungyeong98
 */
@Service
@RequiredArgsConstructor
public class ApiV1MemberService implements MemberService {
	private final MemberRepository memberRepository;
	private final PasswordEncoder passwordEncoder;

	@Override
	@Transactional
	public Member signup(SignupRequest request) {
		memberRepository.findByEmail(request.getEmail()).ifPresent(member -> {
			throw new ServiceException(ErrorCode.DUPLICATE_EMAIL);
		});
		Member member = Member.builder()
			.email(request.getEmail())
			.password(passwordEncoder.encode(request.getPassword()))
			.name(request.getName())
			.phone(request.getPhone())
			.memberId(request.getEmail())
			.build();
		return memberRepository.save(member);
	}
}
