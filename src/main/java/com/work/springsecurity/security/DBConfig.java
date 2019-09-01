package com.work.springsecurity.security;


import java.util.Random;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

@Configuration
public class DBConfig {

  @Bean(value = "dataSource")
  public DriverManagerDataSource dataSource() {
    DriverManagerDataSource dmds = new DriverManagerDataSource();
    dmds.setDriverClassName("com.mysql.jdbc.Driver");
    dmds.setUrl("jdbc:mysql://localhost/sakila?useUnicode=true&amp;characterEncoding=UTF-8&amp;autoReconnect=true");
    dmds.setUsername("root");
    dmds.setPassword("");
    return dmds;
  }

  @Bean(value = "randomSum")
  public Random rnd() {

    return new Random();
  }

}
