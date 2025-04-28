
# JWT 인증/인가 구현 가이드

## ps
해당 레포지터리는 이전에 진행했던 프로젝트들에서 사용했던 코드들의 대대적인 리펙토링 겸 연습용입니다. <br>
기초적인 유저 엔티티를 사용해서 인증/인가를 구현했기 때문에, 필요에 따라 수정하여 사용하시면 됩니다. <br>
대부분의 코드들은 SonarQube를 통해 검토 + postman으로 실행하여 결과를 확인한 후 올린 코드들로 웬만하면 문제가 없을 겁니다. <br>

## 목차
1. [인증/인가 기능 개요](#인증인가-기능-개요)
2. [일반 로그인 프로세스](#일반-로그인-프로세스)
3. [소셜 로그인 프로세스](#소셜-로그인-프로세스)
4. [패키지 구조](#패키지-구조)
5. [주요 클래스 역할](#주요-클래스-역할)

## 인증/인가 기능 개요

이 프로젝트는 Spring Security와 JWT를 사용하여 다음과 같은 인증 및 인가 기능을 구현했습니다:

### 구현된 인증(Authentication) 기능
- 이메일/비밀번호 기반 일반 로그인
- 소셜 로그인 (Google, Kakao)
- JWT 토큰 발급 및 관리
- 로그아웃 처리

### 구현된 인가(Authorization) 기능
- JWT 토큰 검증
- 보호된 리소스에 대한 접근 제어
- 사용자 역할 기반 권한 관리

## 일반 로그인 프로세스

일반 로그인은 다음과 같은 단계로 처리됩니다:

1. **로그인 요청**
   - 클라이언트가 `/api/v1/login` 엔드포인트로 이메일과 비밀번호를 포함한 JSON 요청을 전송합니다.

2. **인증 필터 처리**
   - `JwtAuthenticationFilter`가 로그인 요청을 가로채고 처리합니다.
   - `attemptAuthentication` 메서드에서 요청 본문에서 이메일과 비밀번호를 추출합니다.
   - `UsernamePasswordAuthenticationToken`을 생성하여 `AuthenticationManager`에 전달합니다.

3. **사용자 정보 로드**
   - `CustomUserDetailsService`가 이메일을 기반으로 데이터베이스에서 사용자 정보를 로드합니다.
   - 로드된 사용자 정보를 `CustomUserDetails` 객체로 변환합니다.

4. **비밀번호 검증**
   - `AuthenticationManager`가 제공된 비밀번호와 저장된 비밀번호를 비교합니다.
   - 비밀번호가 일치하면 인증 성공, 일치하지 않으면 인증 실패 처리됩니다.

5. **JWT 토큰 생성**
   - 인증 성공 시 `JwtTokenProvider`의 `saveToken` 메서드가 호출됩니다.
   - `AccessTokenService`가 사용자 ID와 역할 정보를 포함한 JWT 액세스 토큰을 생성합니다.
   - `RefreshTokenService`가 리프레시 토큰을 생성합니다.

6. **토큰 저장 및 응답**
   - 생성된 액세스 토큰은 HTTP Only 쿠키로 설정됩니다.
   - 리프레시 토큰은 Redis에 저장되며 액세스 토큰과 매핑됩니다.
   - 성공 응답이 클라이언트에게 반환됩니다.

## 소셜 로그인 프로세스

소셜 로그인(Google, Kakao)은 다음과 같은 단계로 처리됩니다:

1. **소셜 로그인 요청**
   - 사용자가 소셜 로그인 버튼을 클릭하면 OAuth2 인증 서버로 리다이렉트됩니다.
   - 사용자가 소셜 서비스에서 인증을 완료하면 인증 코드와 함께 애플리케이션으로 리다이렉트됩니다.

2. **OAuth2 인증 처리**
   - Spring Security의 OAuth2 클라이언트가 인증 코드를 처리하고 액세스 토큰을 요청합니다.
   - 소셜 서비스 제공자(Google, Kakao)로부터 사용자 정보를 가져옵니다.

3. **사용자 정보 로드**
   - `CustomOAuth2UserService`의 `loadUser` 메서드가 호출됩니다.
   - 소셜 서비스 ID(registrationId)와 사용자 속성(attributes)을 기반으로 `OAuth2UserInfo` 객체를 생성합니다.
   - `OAuth2UserInfoFactory`를 통해 소셜 로그인 타입에 맞는 구현체(GoogleOAuth2UserInfo, KakaoOAuth2UserInfo)를 생성합니다.

4. **사용자 정보 저장**
   - 이메일을 기준으로 기존 사용자가 있는지 확인합니다.
   - 기존 사용자가 없으면 새로운 사용자로 등록합니다.

5. **인증 성공 처리**
   - `OAuth2LoginSuccessHandler`의 `onAuthenticationSuccess` 메서드가 호출됩니다.
   - 소셜 로그인 사용자의 이메일을 기반으로 회원 정보를 조회합니다.
   - 기존 회원인 경우 JWT 토큰을 생성하고 쿠키에 저장합니다.
   - 새로운 사용자인 경우 추가 회원가입 절차를 진행할 수 있습니다(현재는 바로 처리).

6. **토큰 발급 및 리다이렉트**
   - 일반 로그인과 동일하게 JWT 토큰이 생성되고 쿠키에 저장됩니다.
   - 사용자는 프론트엔드 URL로 리다이렉트됩니다.

## 패키지 구조

프로젝트의 패키지 구조는 다음과 같이 구성되어 있습니다:

```
com.jwt_code_practice
├── domain
│   └── member
│       ├── controller
│       ├── dto
│       ├── entity
│       ├── repository
│       └── service
└── global
    ├── config
    ├── exception
    └── security
        ├── constants
        ├── dto
        ├── filter
        ├── handler
        ├── jwt
        ├── oauth
        │   ├── dto
        │   ├── handler
        │   ├── model
        │   └── service
        └── user
```

### 주요 패키지 설명

1. **domain/member**: 사용자 관련 도메인 로직
   - `controller`: 사용자 관련 API 엔드포인트
   - `dto`: 데이터 전송 객체
   - `entity`: 사용자 엔티티 클래스
   - `repository`: 데이터 접근 계층
   - `service`: 비즈니스 로직

2. **global/security**: 보안 관련 구성 및 구현
   - `constants`: 보안 관련 상수 정의
   - `dto`: 보안 관련 데이터 전송 객체
   - `filter`: JWT 인증 및 인가 필터
   - `handler`: 인증 성공/실패 핸들러
   - `jwt`: JWT 토큰 관련 서비스
   - `oauth`: 소셜 로그인 관련 구현
   - `user`: 사용자 인증 정보 관리

## 주요 클래스 역할

### 보안 설정

1. **SecurityConfig**
   - Spring Security 설정을 담당하는 클래스
   - 보안 필터 체인 구성, CORS 설정, 세션 관리 정책 설정, URL 기반 접근 제어 설정
   - JWT 필터와 OAuth2 로그인 설정을 통합

### JWT 관련 클래스

1. **JwtTokenProvider**
   - JWT 토큰 생성 및 검증을 담당하는 핵심 클래스
   - 액세스 토큰 및 리프레시 토큰 생성, HTTP 요청에서 토큰 추출, 토큰 유효성 검증, 로그아웃 처리

2. **AccessTokenService**
   - JWT 액세스 토큰의 생성, 검증, 추출 및 블랙리스트 관리
   - 일반 로그인과 소셜 로그인 모두 지원

3. **RefreshTokenService**
   - 리프레시 토큰 생성 및 관리
   - 액세스 토큰과 리프레시 토큰의 매핑 정보 관리

4. **TokenUtilService**
   - 토큰 유효성 검증, 클레임 추출 등 토큰 관련 유틸리티 기능 제공

5. **CookieService**
   - HTTP 쿠키 생성 및 관리
   - 토큰을 쿠키로 설정하고 쿠키에서 토큰 추출

### 인증 필터

1. **JwtAuthenticationFilter**
   - 로그인 요청을 처리하고 JWT 토큰을 생성하여 응답
   - 이메일/비밀번호 기반 인증 처리

2. **JwtAuthorizationFilter**
   - 모든 요청에 대해 JWT 토큰을 검증하고 인증 정보를 설정
   - 보호된 리소스에 대한 접근 제어

### 소셜 로그인 관련 클래스

1. **CustomOAuth2UserService**
   - OAuth2 인증 후 사용자 정보를 로드하고 처리
   - 소셜 로그인 사용자 정보를 애플리케이션 사용자 정보로 변환

2. **OAuth2LoginSuccessHandler**
   - 소셜 로그인 성공 시 호출되는 핸들러
   - JWT 토큰 생성 및 응답 처리

3. **OAuth2UserInfoFactory**
   - 소셜 로그인 제공자(Google, Kakao)에 따라 적절한 OAuth2UserInfo 구현체 생성

4. **GoogleOAuth2UserInfo / KakaoOAuth2UserInfo**
   - 각 소셜 로그인 제공자별 사용자 정보 추출 로직 구현

### 사용자 인증 정보 관리

1. **CustomUserDetails**
   - Spring Security의 UserDetails 인터페이스 구현
   - 인증된 사용자 정보 표현

2. **CustomUserDetailsService**
   - 사용자 이메일을 기반으로 데이터베이스에서 사용자 정보를 로드
   - UserDetailsService 인터페이스 구현

이 구현은 보안성과 확장성을 고려하여 설계되었으며, 일반 로그인과 소셜 로그인을 모두 지원합니다. JWT 토큰 기반의 인증 시스템은 상태를 유지하지 않는(stateless) RESTful API에 적합하며, 토큰 갱신 및 로그아웃 기능도 구현되어 있습니다.
