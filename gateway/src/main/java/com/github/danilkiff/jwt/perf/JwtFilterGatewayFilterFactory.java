package com.github.danilkiff.jwt.perf;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.stereotype.Component;

@Component
public class JwtFilterGatewayFilterFactory extends AbstractGatewayFilterFactory<Object> {
    private final JwtFilter jwtFilter;

    public JwtFilterGatewayFilterFactory(JwtFilter jwtFilter) {
        this.jwtFilter = jwtFilter;
    }

    @Override
    public GatewayFilter apply(Object o) {
        return jwtFilter::filter;
    }
}
