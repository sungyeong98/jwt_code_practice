package com.jwt_code_practice.domain.member.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.jwt_code_practice.domain.member.dto.request.SignupRequest;
import com.jwt_code_practice.domain.member.dto.response.SignupResponse;
import com.jwt_code_practice.domain.member.entity.Member;
import com.jwt_code_practice.domain.member.service.MemberService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * 사용자 컨트롤러 클래스
 * @version 1.0
 * @author sungyeong98
 */
@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/members")
public class ApiV1MemberController {
	private final MemberService memberService;

	@PostMapping("/signup")
	public ResponseEntity<SignupResponse> signup(
		@Valid @RequestBody SignupRequest request) {
		log.info("회원가입 로직 실행 중...");
		Member member = memberService.signup(request);
		return ResponseEntity.ok(SignupResponse.of(member));
	}
}
