package net.suuku.gateway.config;

import net.suuku.gateway.aop.logging.LoggingAspect;
import org.springframework.context.annotation.*;
import org.springframework.core.env.Environment;
import tech.jhipster.config.JHipsterConstants;

@Configuration
@EnableAspectJAutoProxy
public class LoggingAspectConfiguration {

    @Bean
    @Profile(JHipsterConstants.SPRING_PROFILE_DEVELOPMENT)
    LoggingAspect loggingAspect(Environment env) {
        return new LoggingAspect(env);
    }
}
