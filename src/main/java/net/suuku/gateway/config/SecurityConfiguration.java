package net.suuku.gateway.config;

import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.PREFERRED_USERNAME;
import static org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers.pathMatchers;

import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity.OAuth2ResourceServerSpec;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistration.ProviderDetails;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.logout.DelegatingServerLogoutHandler;
import org.springframework.security.web.server.authentication.logout.SecurityContextServerLogoutHandler;
import org.springframework.security.web.server.authentication.logout.WebSessionServerLogoutHandler;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.server.header.ReferrerPolicyServerHttpHeadersWriter;
import org.springframework.security.web.server.header.XFrameOptionsServerHttpHeadersWriter.Mode;
import org.springframework.security.web.server.util.matcher.NegatedServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.OrServerWebExchangeMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import net.suuku.gateway.security.AuthoritiesConstants;
import net.suuku.gateway.security.SecurityUtils;
import net.suuku.gateway.security.oauth2.AudienceValidator;
import net.suuku.gateway.web.filter.SpaWebFilter;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import tech.jhipster.config.JHipsterProperties;
import tech.jhipster.web.filter.reactive.CookieCsrfFilter;

@Configuration
@EnableReactiveMethodSecurity
public class SecurityConfiguration {

    private final JHipsterProperties jHipsterProperties;
    private static final Logger LOG = LoggerFactory.getLogger(SecurityConfiguration.class);
    private final JwtDecoder jwtDecoder;
    
    @Value("${spring.security.oauth2.client.registration.client-id:}")
	private String  clientId;

    @Value("${spring.security.oauth2.client.provider.oidc.issuer-uri:}")
    private String issuerUri;

    private final ReactiveClientRegistrationRepository clientRegistrationRepository;
    
    DelegatingServerLogoutHandler logoutHandler = new DelegatingServerLogoutHandler(
            new SecurityContextServerLogoutHandler(), new WebSessionServerLogoutHandler()
    );

    // See https://github.com/jhipster/generator-jhipster/issues/18868
    // We don't use a distributed cache or the user selected cache implementation here on purpose
    private final Cache<String, Mono<Jwt>> users = Caffeine.newBuilder()
        .maximumSize(10_000)
        .expireAfterWrite(Duration.ofHours(1))
        .recordStats()
        .build();

    public SecurityConfiguration(ReactiveClientRegistrationRepository clientRegistrationRepository, JHipsterProperties jHipsterProperties, JwtDecoder jwtDecoder) {
        this.jwtDecoder = jwtDecoder;
		this.clientRegistrationRepository = clientRegistrationRepository;
        this.jHipsterProperties = jHipsterProperties;
    }

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
            .securityMatcher(
                new NegatedServerWebExchangeMatcher(
                    new OrServerWebExchangeMatcher(pathMatchers("/app/**", "/i18n/**", "/content/**", "/swagger-ui/**"))
                )
            )
            .cors(withDefaults())
            .csrf(csrf ->
                csrf
                    .csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse())
                    // See https://stackoverflow.com/q/74447118/65681
                    .csrfTokenRequestHandler(new ServerCsrfTokenRequestAttributeHandler())
                    
            )
            // See https://github.com/spring-projects/spring-security/issues/5766
            .addFilterAt(new CookieCsrfFilter(), SecurityWebFiltersOrder.REACTOR_CONTEXT)
            .addFilterAfter(new SpaWebFilter(), SecurityWebFiltersOrder.HTTPS_REDIRECT)
            .headers(headers ->
                headers
                    .contentSecurityPolicy(csp -> csp.policyDirectives(jHipsterProperties.getSecurity().getContentSecurityPolicy()))
                    .frameOptions(frameOptions -> frameOptions.mode(Mode.DENY))
                    .referrerPolicy(referrer ->
                        referrer.policy(ReferrerPolicyServerHttpHeadersWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)
                    )
                    .permissionsPolicy(permissions ->
                        permissions.policy(
                            "camera=(), fullscreen=(self), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), sync-xhr=()"
                        )
                    )
            )
            .authorizeExchange(authz ->
                // prettier-ignore
                authz
                .pathMatchers("/").permitAll()
                .pathMatchers("/*.*").permitAll()
                .pathMatchers("/api/authenticate").permitAll()
                .pathMatchers("/api/auth-info").permitAll()
                .pathMatchers("/api/admin/**").hasAuthority(AuthoritiesConstants.ADMIN)
                .pathMatchers("/api/**").authenticated()
                .pathMatchers("/services/*/management/health/readiness").permitAll()
                .pathMatchers("/services/*/v3/api-docs").hasAuthority(AuthoritiesConstants.ADMIN)
                .pathMatchers("/services/**").authenticated()
                .pathMatchers("/v3/api-docs/**").hasAuthority(AuthoritiesConstants.ADMIN)
                .pathMatchers("/management/health").permitAll()
                .pathMatchers("/management/health/**").permitAll()
                .pathMatchers("/management/info").permitAll()
                .pathMatchers("/management/prometheus").permitAll()
                .pathMatchers("/management/**").hasAuthority(AuthoritiesConstants.ADMIN)
        )
            .oauth2Login(oauth2 -> 	oauth2
            		.authorizationRequestResolver(authorizationRequestResolver(this.clientRegistrationRepository))
            		)
            .logout((logout) -> logout.logoutHandler(logoutHandler))
            .oauth2Client(withDefaults())
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()))
            .headers(headers -> headers
        			.contentSecurityPolicy(policy -> policy
        				.policyDirectives("script-src 'self' https://trustedscripts.example.com; object-src https://trustedplugins.example.com; report-uri /csp-report-endpoint/")
        			));
        return http.build();
    }

    private ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver(
        ReactiveClientRegistrationRepository clientRegistrationRepository
    ) {
        DefaultServerOAuth2AuthorizationRequestResolver authorizationRequestResolver = new DefaultServerOAuth2AuthorizationRequestResolver(
            clientRegistrationRepository
        );
        if (this.issuerUri.contains("auth0.com")) {
            authorizationRequestResolver.setAuthorizationRequestCustomizer(authorizationRequestCustomizer());
        }
        return authorizationRequestResolver;
    }

    private Consumer<OAuth2AuthorizationRequest.Builder> authorizationRequestCustomizer() {
        return customizer ->
            customizer.authorizationRequestUri(uriBuilder ->
                uriBuilder.queryParam("audience", jHipsterProperties.getSecurity().getOauth2().getAudience()).build()
            );
    }


    /**
     * Map authorities from "groups" or "roles" claim in ID Token.
     *
     * @return a {@link ReactiveOAuth2UserService} that has the groups from the IdP.
     */
    @Bean
    public ReactiveOAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        final OidcReactiveOAuth2UserService delegate = new OidcReactiveOAuth2UserService();

        return userRequest -> {
            // Delegate to the default implementation for loading a user
            return delegate
                .loadUser(userRequest)
                .flatMap((oidcUser) -> {
					String accessToken = userRequest.getAccessToken().getTokenValue();
					
					// 1) Fetch the authority information from the protected resource using accessToken
					Set<GrantedAuthority> oidcAuthorities = new HashSet<>(extractKeycloakRoles(accessToken));
					// 2) Map the authority information to one or more GrantedAuthority
					oidcAuthorities.addAll(oidcUser.getAuthorities());
					// 3) Create a copy of oidcUser but use the mappedAuthorities instead
					ProviderDetails providerDetails = userRequest.getClientRegistration().getProviderDetails();
					String userNameAttributeName = providerDetails.getUserInfoEndpoint().getUserNameAttributeName();
					if (StringUtils.hasText(userNameAttributeName)) {
						oidcUser = new DefaultOidcUser(oidcAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo(), userNameAttributeName);
					} else {
						oidcUser = new DefaultOidcUser(oidcAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
					}

					return Mono.just(oidcUser);
				});
        };
	}
    
    private Set<GrantedAuthority> extractKeycloakRoles(String accessToken) {
		// Decode Jwt Token
    	Jwt jwt = jwtDecoder.decode(accessToken);
    	
    
    	Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
    	if (realmAccess == null) {
    		// Make extractKeycloakRoles() always return a mutable set. 
    		// return new HashSet instead of a Collections.emptySet();
    		LOG.info("Empty realAccess: {}", realmAccess);
    		return Collections.emptySet();
    	}
    	
    	LOG.info("resourceAccess: {}", realmAccess);
    	
    	@SuppressWarnings("unchecked")
		List<String> roles = (List<String>) realmAccess.get("roles");
    	if(roles == null || roles.isEmpty()) {
    		return Collections.emptySet();
    	}
 
    	return  roles.stream()
    			.filter(String.class::isInstance)
    	        .map(String.class::cast)
    			.map(role -> new SimpleGrantedAuthority(role.toUpperCase()))
    			.collect(Collectors.toSet());
    	
	}


	@Bean
    ReactiveJwtDecoder jwtDecoder(ReactiveClientRegistrationRepository registrations) {
        Mono<ClientRegistration> clientRegistration = registrations.findByRegistrationId("oidc");

        return clientRegistration
            .map(oidc ->
                createJwtDecoder(
                    oidc.getProviderDetails().getIssuerUri(),
                    oidc.getProviderDetails().getJwkSetUri(),
                    oidc.getProviderDetails().getUserInfoEndpoint().getUri()
                )
            )
            .block();
    }

    private ReactiveJwtDecoder createJwtDecoder(String issuerUri, String jwkSetUri, String userInfoUri) {
        NimbusReactiveJwtDecoder jwtDecoder = new NimbusReactiveJwtDecoder(jwkSetUri);
        OAuth2TokenValidator<Jwt> audienceValidator = new AudienceValidator(jHipsterProperties.getSecurity().getOauth2().getAudience());
        OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuerUri);
        OAuth2TokenValidator<Jwt> withAudience = new DelegatingOAuth2TokenValidator<>(withIssuer, audienceValidator);

        jwtDecoder.setJwtValidator(withAudience);

        return new ReactiveJwtDecoder() {
            @Override
            public Mono<Jwt> decode(String token) throws JwtException {
                return jwtDecoder.decode(token).flatMap(jwt -> enrich(token, jwt));
            }

            private Mono<Jwt> enrich(String token, Jwt jwt) {
                // Only look up user information if identity claims are missing
                if (jwt.hasClaim("given_name") && jwt.hasClaim("family_name")) {
                    return Mono.just(jwt);
                }
                // Get user info from `users` cache if present
                return Optional.ofNullable(users.getIfPresent(jwt.getSubject())).orElseGet(() -> // Retrieve user info from OAuth provider if not already loaded
                    WebClient.create()
                        .get()
                        .uri(userInfoUri)
                        .headers(headers -> headers.setBearerAuth(token))
                        .retrieve()
                        .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                        .map(userInfo ->
                            Jwt.withTokenValue(jwt.getTokenValue())
                                .subject(jwt.getSubject())
                                .audience(jwt.getAudience())
                                .headers(headers -> headers.putAll(jwt.getHeaders()))
                                .claims(claims -> {
                                    String username = userInfo.get("preferred_username").toString();
                                    // special handling for Auth0
                                    if (userInfo.get("sub").toString().contains("|") && username.contains("@")) {
                                        userInfo.put("email", username);
                                    }
                                    // Allow full name in a name claim - happens with Auth0
                                    if (userInfo.get("name") != null) {
                                        String[] name = userInfo.get("name").toString().split("\\s+");
                                        if (name.length > 0) {
                                            userInfo.put("given_name", name[0]);
                                            userInfo.put("family_name", String.join(" ", Arrays.copyOfRange(name, 1, name.length)));
                                        }
                                    }
                                    claims.putAll(userInfo);
                                })
                                .claims(claims -> claims.putAll(jwt.getClaims()))
                                .build()
                        )
                        // Put user info into the `users` cache
                        .doOnNext(newJwt -> users.put(jwt.getSubject(), Mono.just(newJwt)))
                );
            }
        };
    }
}