package backend.app.premier_chat.exception_handling;

import org.springframework.context.support.DefaultMessageSourceResolvable;
import org.springframework.validation.BindingResult;

import java.util.stream.Collectors;

public class Validation {

    private static String getMessages(BindingResult validation) {
        return validation.getAllErrors().parallelStream().map(DefaultMessageSourceResolvable::getDefaultMessage)
                .collect(Collectors.joining(". "));
    }

    public static void verify(BindingResult validation) throws BadRequestException {
        if (validation.hasErrors()) throw new BadRequestException(getMessages(validation));
    }

}
