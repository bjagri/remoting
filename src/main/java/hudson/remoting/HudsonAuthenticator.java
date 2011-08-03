/*
 *  The MIT License
 * 
 *  Copyright 2010 Laszlo Kishalmi.
 * 
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 * 
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 * 
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  THE SOFTWARE.
 */

package hudson.remoting;

import java.io.IOException;
import java.io.OutputStream;
import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

/**
 * This Authenticator allows Hudson slaves to authenticate to master via
 * HTTP Basic or Form based authentication.
 *
 * @author Laszlo Kishalmi
 */
final class HudsonAuthenticator {

    private static final String GUESS_COMPUTER = "/computer/";
    private static final String GUESS_JENKINS = "/jenkins/";

    private final transient String user;
    private final transient String password;

    private AuthStrategy testedStrategy;
    private final AuthStrategy[] strategies = {
        new HTTPBasicStrategy(),
        new ServletStrategy("j_acegi_security_check"),
        new ServletStrategy("j_security_check"),
    };

    public HudsonAuthenticator(String user, String password) {
        this.user = user;
        this.password = password;
    }

    /**
     * Initialize a new authenticator from colon separated user and password
     * string.
     *
     * @param credentials teh colon separated user:passwd string.
     * @throws IllegalArgumentException if there is no colon in the credentials
     *         string.
     */
    public HudsonAuthenticator(String credentials) {
        int idx = credentials.indexOf(':');
        if (idx > 0) {
            user = credentials.substring(0, idx);
            password = credentials.substring(idx + 1);
        } else {
            throw new IllegalArgumentException("Cannot interpret credentials as <user>:<password>");
        }
    }

    /**
     * Tries to return an authenticated HttpURLConnection. The returned
     * connection will be connected already!
     *
     * <p>
     * This method does not need the hudson home URL, as it tries to find it
     * out guessing on if the given URL. The given url shall contain
     * "/computer/" or "/jenkins/" in order to make the guessing
     * work.
     * </p>
     *
     * @param base the Hudson context root. Like http://localhost/jenkins/
     * @return An authenticated HttpURLConnection.
     * @throws IOException if none of the applicable authentication strategies
     *         worked.
     */
    public HttpURLConnection authConnection(URL url) throws IOException {
        String guess = url.toExternalForm();
        URL base;
        String rel;
        if (guess.contains(GUESS_COMPUTER)) {
            int idx = guess.indexOf(GUESS_COMPUTER) + 1;
            base = new URL(guess.substring(0, idx));
            rel = guess.substring(idx);
        } else if (guess.contains(GUESS_JENKINS)) {
            int idx = guess.indexOf(GUESS_JENKINS) + GUESS_JENKINS.length();
            base = new URL(guess.substring(0, idx));
            rel = guess.substring(idx);
        } else {
            base = url;
            rel = "";
        }
        return authConnection(base, rel);
    }

    /**
     * Tries to return an authenticated HttpURLConnection. The returned
     * connection will be connected already!
     *
     * @param base the Hudson context root. Like http://localhost/jenkins/
     * @param rel the relative part of the URL to connect to.
     * @return An authenticated HttpURLConnection.
     * @throws IOException if none of the applicable authentication strategies
     *         worked.
     */
    public HttpURLConnection authConnection(URL base, String rel) throws IOException {
        HttpURLConnection ret = null;
        if (testedStrategy != null) {
            ret = testStrategy(testedStrategy, base, rel);
        }
        if (ret == null) {
            for (AuthStrategy auth : strategies) {
                auth.reset();
                ret = testStrategy(auth, base, rel);
                if (ret != null) {
                    testedStrategy = auth;
                    break;

                }
            }
        }
        if (ret == null)
            throw new IOException("None of the authenticators could log in the user: " + user);
        return ret;
    }

    private HttpURLConnection testStrategy(AuthStrategy auth, URL base, String rel) {
        HttpURLConnection ret = null;
        try {
            HttpURLConnection test = auth.authConnection(base, rel, user, password);
            test.connect();
            if(test.getResponseCode() < 300) {
                ret = test;
            }
        } catch (IOException ex) {
            LOGGER.warning(ex.getMessage());
        }
        return ret;
    }

    private interface AuthStrategy {
        HttpURLConnection authConnection(URL base, String rel, String user, String passwd) throws IOException;
        void reset();
    }


    private static class HTTPBasicStrategy implements AuthStrategy {

        public HttpURLConnection authConnection(URL base, String rel, String user, String passwd) throws  IOException {
            URL url = new URL(getBase(base), rel);

            LOGGER.fine("Trying to authenticate with HTTP Basic to " + url.toExternalForm());
            HttpURLConnection http = (HttpURLConnection) url.openConnection();
            String credentials = user + ":" + passwd;
            String encoding = new sun.misc.BASE64Encoder().encode (credentials.getBytes());
            http.setRequestProperty ("Authorization", "Basic " + encoding);
            return http;
        }

        public void reset() {
        }
    }

    private static class ServletStrategy implements AuthStrategy {
        private final String loginPath;
        private final Set<String> authenticatedUsers = new HashSet<String>();

        static {
            // This strategy needs a system configured CookieHandler.
            CookieHandler ch = CookieHandler.getDefault();
            if (ch == null) {
                LOGGER.finer("Initialize a new CookieHandler.");
                CookieHandler.setDefault(new CookieManager(null, CookiePolicy.ACCEPT_ALL));
            }
        }

        public ServletStrategy(String loginPath) {
            this.loginPath = loginPath;
        }

        public HttpURLConnection authConnection(URL base, String rel, String user, String passwd)  throws  IOException {
            if (!authenticatedUsers.contains(user)) {
                URL login = new URL(getBase(base), loginPath);

                LOGGER.fine("Trying to authenticate using form to " + login.toExternalForm());
                String authData = "j_username=" + user + "&j_password=" + passwd;
                HttpURLConnection conn = (HttpURLConnection) login.openConnection();
                conn.setInstanceFollowRedirects(false);
                conn.setDoOutput(true);
                conn.connect();
                OutputStream os = conn.getOutputStream();
                os.write(authData.getBytes());
                os.close();
                String redirect = conn.getRequestProperty("Location");
                if (((redirect != null) && redirect.endsWith("loginError")) || (conn.getResponseCode() >= 400)) {
                    throw new IOException("Not able to login user: " + user + " on " + login);
                } else {
                    authenticatedUsers.add(user);                    
                }
            }
            URL url = new URL(getBase(base), rel);
            return  (HttpURLConnection) url.openConnection();
        }

        public void reset() {
            authenticatedUsers.clear();
        }

    }

    private final static URL getBase(URL base) throws MalformedURLException {
        String s = base.toExternalForm();
        return s.endsWith("/") ? base : new URL(s + '/');
    }

    private static final Logger LOGGER = Logger.getLogger(HudsonAuthenticator.class.getName());
}
