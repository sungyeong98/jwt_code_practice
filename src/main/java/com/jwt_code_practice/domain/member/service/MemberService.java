package com.jwt_code_practice.domain.member.service;

import com.jwt_code_practice.domain.member.dto.request.SignupRequest;
import com.jwt_code_practice.domain.member.entity.Member;

/**
 * 사용자 서비스 클래스
 * @author sungyeong98
 */
public interface MemberService {
	Member signup(SignupRequest request);
}
