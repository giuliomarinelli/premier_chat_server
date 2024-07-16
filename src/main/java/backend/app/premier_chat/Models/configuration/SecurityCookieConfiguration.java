package backend.app.premier_chat.Models.configuration;


import lombok.Data;

@Data
public class SecurityCookieConfiguration {

    private String path;
    private boolean httpOnly;
    private String sameSite;
    private boolean secure;
    private String domain;
    private int maxAge;

    public SecurityCookieConfiguration(String path, boolean httpOnly, String sameSite, boolean secure, String domain, long maxAgeMs) {
        this.path = path;
        this.httpOnly = httpOnly;
        this.sameSite = sameSite;
        this.secure = secure;
        this.domain = domain;
        maxAge = (int) maxAgeMs / 1000;
    }

}
