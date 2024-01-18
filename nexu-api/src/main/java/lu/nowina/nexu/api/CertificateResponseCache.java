package lu.nowina.nexu.api;


import java.util.List;

public class CertificateResponseCache {
        private static CertificateResponseCache instance;

        private GetCertificateResponse certificateResponse;
        private String digestAlgorithm;
        private Boolean rememberPassword;

        private CertificateResponseCache() {
            // Private constructor to prevent instantiation
        }

        public static CertificateResponseCache getInstance() {
            if (instance == null) {
                instance = new CertificateResponseCache();
            }
            return instance;
        }

        public GetCertificateResponse getCertificateResponse() {
            return certificateResponse;
        }

        public void setCertificateResponse(GetCertificateResponse certificateResponse) {
            this.certificateResponse = certificateResponse;
        }

        public String getDigestAlgorithm() {
            return digestAlgorithm;
        }

        public void setDigestAlgorithm(String digestAlgorithm) {
            this.digestAlgorithm = digestAlgorithm;
        }

        public Boolean getRememberPassword() {
        return rememberPassword;
    }

        public void setRememberPassword(Boolean rememberPassword) {
        this.rememberPassword = rememberPassword;
    }

}
