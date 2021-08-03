package burp.core.scanner.active.jwtscanner;

public interface IJWTConstant {
    String regexpJwtPattern = "(ey[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9._-]{10,}|ey[A-Za-z0-9_/+-]{10,}\\.[A-Za-z0-9._/+-]{10,})";

    enum NoneFlag {
        none, None, NONE, nOne
    }
}
