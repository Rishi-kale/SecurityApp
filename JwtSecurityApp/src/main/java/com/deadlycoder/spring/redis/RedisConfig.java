//package com.deadlycoder.spring.redis;
//
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
//import org.springframework.data.redis.core.RedisTemplate;
//import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
//import org.springframework.data.redis.serializer.RedisSerializer;
//
//@Configuration
//public class RedisConfig {
//
//    @Value("${spring.redis.host}")
//    private String redisHost;  // Fix the typo from redistHost to redisHost
//
//    @Value("${spring.redis.port}")
//    private int redisPort;
//
//    @Bean
//    JedisConnectionFactory jedisConnectionFactory() {
//        JedisConnectionFactory jedisConFactory = new JedisConnectionFactory();
//        jedisConFactory.setHostName(redisHost);
//        jedisConFactory.setPort(redisPort);
//        return jedisConFactory;
//    }
//
//    @Bean
//    public RedisTemplate<String, Object> redisTemplate() {
//        RedisTemplate<String, Object> template = new RedisTemplate<>();
//        template.setConnectionFactory(jedisConnectionFactory());
//        template.setDefaultSerializer(new GenericJackson2JsonRedisSerializer()); // Use JSON serialization
//        return template;
//    }
//}
