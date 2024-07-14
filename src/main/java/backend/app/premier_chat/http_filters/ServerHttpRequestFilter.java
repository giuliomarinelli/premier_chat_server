//package backend.app.premier_chat.http_filters;
//
//import org.springframework.core.annotation.Order;
//import org.springframework.http.server.reactive.ServerHttpRequest;
//import org.springframework.stereotype.Component;
//import org.springframework.web.server.ServerWebExchange;
//import org.springframework.web.server.WebFilter;
//import org.springframework.web.server.WebFilterChain;
//import reactor.core.publisher.Mono;
//import reactor.util.annotation.NonNull;
//
//@Component
//@Order(-4)
//public class ServerHttpRequestFilter implements WebFilter {
//
//    @Override
//    @NonNull
//    public Mono<Void> filter(@NonNull ServerWebExchange exchange, @NonNull WebFilterChain chain) {
//        return chain.filter(exchange)
//                .contextWrite(context -> context.put(ServerHttpRequest.class, exchange.getRequest()));
//    }
//}
