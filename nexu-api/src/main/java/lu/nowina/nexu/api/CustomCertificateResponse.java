package lu.nowina.nexu.api;

public class CustomCertificateResponse {
    private boolean success;
    private GetCertificateResponse response;

    public CustomCertificateResponse(boolean success, GetCertificateResponse response) {
        this.success = success;
        this.response = response;
    }

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public GetCertificateResponse getResponse() {
        return response;
    }

    public void setResponse(GetCertificateResponse response) {
        this.response = response;
    }
}
