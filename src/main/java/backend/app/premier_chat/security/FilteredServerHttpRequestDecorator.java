package backend.app.premier_chat.security;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;

public class FilteredServerHttpRequestDecorator extends ServerHttpRequestDecorator {

    private boolean filterApplied = false;

    public FilteredServerHttpRequestDecorator(ServerHttpRequest delegate) {
        super(delegate);
    }

    public boolean isFilterApplied() {
        return filterApplied;
    }

    public void setFilterApplied(boolean filterApplied) {
        this.filterApplied = filterApplied;
    }
}