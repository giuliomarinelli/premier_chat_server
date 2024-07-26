package backend.app.premier_chat.security;

import lombok.Getter;
import lombok.Setter;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;


@Getter
@Setter
public class FilteredServerHttpRequestDecorator extends ServerHttpRequestDecorator {

    private boolean filterApplied = false;

    public FilteredServerHttpRequestDecorator(ServerHttpRequest delegate) {
        super(delegate);
    }

}