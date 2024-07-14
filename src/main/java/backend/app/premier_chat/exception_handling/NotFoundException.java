package backend.app.premier_chat.exception_handling;

public class NotFoundException extends RuntimeException {

    public NotFoundException() {}

    public NotFoundException(String message) {
        super(message);
    }

}
