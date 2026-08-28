package io.github.yaaanni.logix;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.http.HttpMethod;

import java.util.List;

@ConfigurationProperties(prefix = "platform")
public record PlatformConfig(
        @DefaultValue Security security
) {
    public record Security(
            @DefaultValue("true") boolean enabled,
            @DefaultValue List<PublicRule> publicRules,
            @DefaultValue List<RoleRule> roleRules
    ) {}

    public record PublicRule(
            String pattern,
            HttpMethod method
    ) {}

    public record RoleRule(
            String pattern,
            HttpMethod method,
            List<String> roles
    ) {}

    public enum SecurityMode {
        RESOURCE_SERVER,
        CLIENT
    }
}


