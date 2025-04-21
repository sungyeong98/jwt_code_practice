package com.jwt_code_practice.global.config.redis;

import java.util.concurrent.TimeUnit;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;

/**
 * 레디스 레포지터리
 * @author sungyeong98
 */
@Component
@RequiredArgsConstructor
public class RedisRepository {
	private final RedisTemplate<String, Object> redisTemplate;

	/**
	 * redis에 데이터를 저장하는 메서드
	 * @param key 레디스 키
	 * @param value 레디스 값
	 * @param duration 레디스 유효시간
	 * @param timeUnit 시간 단위
	 */
	public void save(String key, Object value, Long duration, TimeUnit timeUnit) {
		redisTemplate.opsForValue().set(key, value, duration, timeUnit);
	}

	/**
	 * redis에서 데이터를 가져오는 메서드
	 * @param key 레디스 키
	 * @return {@link Object} 레디스 값
	 */
	public Object get(String key) {
		return redisTemplate.opsForValue().get(key);
	}

	/**
	 * redis에서 데이터를 삭제하는 메서드
	 * @param key 레디스 키
	 */
	public void remove(String key) {
		redisTemplate.delete(key);
	}
}
