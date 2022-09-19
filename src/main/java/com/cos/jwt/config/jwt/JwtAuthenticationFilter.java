package com.cos.jwt.config.jwt;

import java.io.IOException;
import java.sql.Timestamp;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.JwtProperties;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

// 스프링 스큐리티에서 UsernamePasswordAuthenticationFilter 가 있음
// login 요청해서 username, password 전송하면 (post)
// UsernamePasswordAuthenticationFilter 동작
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private final AuthenticationManager authenticationManager;
	
	// login 요청을 하면 로그인 시도를 위해서 실행되는 함수
	
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException { 
		System.out.println("JwtAuthenticationFilter : 로그인 시도중");
		
		
		try {
			System.out.println(request.getInputStream().toString());
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		System.out.println("===============================");
		
		
		
		// 1. username, password를 받아서
		try {
			
			// -> 1. BufferReader 이용법 
//			BufferedReader br = request.getReader();
//			
//			String input = null;
//			while((input = br.readLine()) != null) {
//				System.out.println(input);
//			}
			
			// 2. json 파싱방법 
			ObjectMapper om = new ObjectMapper();
			User user = om.readValue(request.getInputStream(), User.class);
			
			System.out.println(user);
			
			//token 생성 -> form로그인할때는 자동 생성
			UsernamePasswordAuthenticationToken authenticationToken 
				= new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
			
			// 2. 정상인지 로그인 시도를 해보는 것, authenticationManager로 로그인 시도를 하면! 
			// PricipalDetailsService 호출 loadUserbyUserName() 함수 실행됨
			// DB에 있는 username과 password가 일치한다.
			Authentication authentication = 
					authenticationManager.authenticate(authenticationToken);
			
			
			PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
			
			System.out.println(principalDetails.getUser().getUsername());
			
			// authentication 객체가 session 영역에 저장됨. => 로그인이 되었다는 뜻 // 권한관리 가능
			// 리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는 거임.
			// 굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없음. 근데 단지 권한 처리때문에 session에 넣어준다.
			// 넣어줄 필요가 없다. 원래는 
			return authentication;
			
		} catch(IOException e) {
			e.printStackTrace();
		}
		
		return null;
		
	}

	
	// attempttAuthentication실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행되요.
	// JWT 토큰을 만들어서 request요청한 사용자에게 JWT토큰을 response해주면 됨.
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		
		System.out.println("successfulAuthentication 실행됨: 인증이 완료되었다는 뜻임");
		PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
		
		
		// HASH HMAC512 암호화 방식
		String jwtToken = JWT.create()
							.withSubject("cos토큰")
							.withExpiresAt(new Timestamp(System.currentTimeMillis() + (60000*100))) // 1/1000 s
							.withClaim("id",principalDetails.getUser().getId()) // 비공개 클레임
							.withClaim("username", principalDetails.getUser().getUsername())
							.sign(Algorithm.HMAC512(JwtProperties.SECRET));
		
		System.out.println("jwtToken : "+jwtToken);
		
		response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + jwtToken);
		
		// TODO Auto-generated method stub
		//super.successfulAuthentication(request, response, chain, authResult);
	}
	
	
}
