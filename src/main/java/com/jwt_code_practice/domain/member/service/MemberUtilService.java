package com.jwt_code_practice.domain.member.service;

import com.jwt_code_practice.domain.member.repository.MemberRepository;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class MemberUtilService {
	private final MemberRepository memberRepository;
}
