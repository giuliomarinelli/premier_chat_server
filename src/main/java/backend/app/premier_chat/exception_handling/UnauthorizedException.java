package backend.app.premier_chat.exception_handling;

public class UnauthorizedException extends Exception {

    public UnauthorizedException() {}

    public UnauthorizedException(String message) {
        super(message);
    }

}
