package com.sem4.security_springboot2;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class SecuritySpringBoot2Application {

    public static void main(String[] args) {
        SpringApplication.run(SecuritySpringBoot2Application.class, args);
    }

}

