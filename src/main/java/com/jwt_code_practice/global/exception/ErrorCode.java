package com.jwt_code_practice.global.exception;

import org.springframework.http.HttpStatus;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * 서비스 예외에 사용되는 에러 코드를 정의합니다.
 */
@Getter
@RequiredArgsConstructor
public enum ErrorCode {
	// 공통 에러
	INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "서버 내부 오류가 발생했습니다."),
	INVALID_INPUT_VALUE(HttpStatus.BAD_REQUEST, "유효하지 않은 입력값입니다."),
	METHOD_NOT_ALLOWED(HttpStatus.METHOD_NOT_ALLOWED, "지원하지 않는 HTTP 메서드입니다."),
	ENTITY_NOT_FOUND(HttpStatus.NOT_FOUND, "해당 데이터를 찾을 수 없습니다.");

	private final HttpStatus status;
	private final String message;
}
