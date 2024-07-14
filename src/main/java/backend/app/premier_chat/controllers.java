package backend.app.premier_chat;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class controllers {

    @GetMapping
    public String sayHello() {
        return "Hello";
    }

}
