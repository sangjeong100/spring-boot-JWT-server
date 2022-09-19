package com.cos.jwt.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

	/**
	 * cross-origin
		cross-origin이란 다음 중 한 가지라도 다른 경우를 말합니다.
		
		프로토콜 - http와 https는 프로토콜이 다르다.
		도메인 - domain.com과 other-domain.com은 다르다.
		포트 번호 - 8080포트와 3000포트는 다르다.
	 */
	
	/**
	  * CORS 설정 
	  * 외부 URL에서 api 요청시 허용 필요 
	  */
	@Override
    public void addCorsMappings(CorsRegistry registry) {
        registry
        		.addMapping("/api/**")
        		//.allowedOrigins("*")
        		.allowedMethods("*")
        		.allowedHeaders("*")
        		.allowedOriginPatterns("*")
        		.allowCredentials(true);
    }
}
