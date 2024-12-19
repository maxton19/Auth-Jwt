package com.november.jwtimplementation;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
@EntityScan(basePackages = "com.november.jwtimplementation.model")
class JwtimplementationApplicationTests {

	@Test
	void contextLoads() {
	}

}
