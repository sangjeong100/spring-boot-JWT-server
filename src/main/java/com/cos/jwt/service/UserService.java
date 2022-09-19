package com.cos.jwt.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;

@Service
public class UserService {
	
	@Autowired
	private UserRepository userRepository;
	
	public String signUp(User user) {
		try {
			BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder(); 
			
			user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
			user.setRoles("ROLE_USER");
			userRepository.save(user);
			
			return "SUCCESS";
			
		} catch(Exception e) {
			return "FAIL";
		}
	}

}
