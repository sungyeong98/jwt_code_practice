package com.jwt_code_practice.domain.member.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.jwt_code_practice.domain.member.service.MemberService;

import lombok.RequiredArgsConstructor;

/**
 * 사용자 컨트롤러 클래스
 * @version 1.0
 * @author sungyeong98
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/member")
public class ApiV1MemberController {
	private final MemberService memberService;
}
