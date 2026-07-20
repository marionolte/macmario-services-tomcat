package com.macmario.services.installer;

import com.macmario.general.Version;
import com.macmario.io.file.ReadDir;
import com.macmario.io.file.ReadFile;
import com.macmario.services.coyote.TomcatPasswordCrypt;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * Reads, modifies, and writes Tomcat's server.xml via the DOM API.
 *
 * <p>Resolves server.xml from three forms of input:
 * <ul>
 *   <li>Direct path to {@code server.xml}</li>
 *   <li>Directory containing {@code server.xml}</li>
 *   <li>CATALINA_BASE directory (looks inside {@code conf/server.xml})</li>
 * </ul>
 *
 * <p>Usage:
 * <pre>
 *   java -jar MHService-tomcat-1.0.jar -update /opt/tomcat adminport=17005
 *   java -jar MHService-tomcat-1.0.jar -update /opt/tomcat httpport=17080
 *   java -jar MHService-tomcat-1.0.jar -update /opt/tomcat httpsport=17443
 *   java -jar MHService-tomcat-1.0.jar -update /opt/tomcat ajpport=17009
 *   java -jar MHService-tomcat-1.0.jar -update /opt/tomcat adminport=17005 httpport=17080 httpsport=17443 ajpport=17009
 * </pre>
 */
class TomcatConfig extends Version {

    private final ReadFile rf;
    private Document doc = null;

    // Old/new port pairs captured before DOM modification — used by updateServerXML()
    // to apply targeted text substitutions without touching unrelated connectors.
    private int httpPortOld  = -1;
    private int httpPortNew  = -1;
    private int sslPortOld   = -1;
    private int sslPortNew   = -1;
    private int ajpPortOld   = -1;
    private int ajpPortNew   = -1;

    TomcatConfig(String info) {
        rf = findServerXml(info);
        if (rf != null) readServerXml();
    }

    /**
     * Replaces Tomcat's built-in class names with {@code com.macmario} equivalents in server.xml.
     *
     * <p>Targets the XML attributes {@code className}, {@code protocol}, {@code factory}, and
     * {@code type} — covering Connectors, Listeners, Realms, Valves, and DataSource Resources.
     * All other content (comments, whitespace, port values) is preserved exactly.
     *
     * <p>Example:
     * <pre>
     *   className="org.apache.catalina.valves.AccessLogValve"
     *   →  className="com.macmario.catalina.valves.AccessLogValve"
     *
     *   factory="org.apache.tomcat.jdbc.pool.DataSourceFactory"
     *   →  factory="com.macmario.tomcat.jdbc.pool.DataSourceFactory"
     * </pre>
     *
     * @return {@code true} when at least one class name was replaced and the file was written
     */
    boolean install() { 
        boolean b = addJarToTomcat();
        if (b) b=replaceClasses("org.apache.", "install");
        if (b) b=replacePassword(true); 
        return b;
    }

     private boolean addJarToTomcat() {
        boolean b=false;  
        if ( rf != null ) {
            ReadDir tc = new ReadDir( rf.getParent().getAbsolutePath()+_FS+".."+_FS+"lib" );
            if ( tc.isDirectory() ) {
                ReadFile jar = new ReadFile(jarfile);
                b=jar.copy(new File(tc.getAbsolutePath()+_FS+jar.getFileName()));
            }
        }        
        return b;
     }
    
    /**
     * Restores Tomcat's built-in class names in server.xml, reversing a previous {@link #install()}.
     *
     * <p>Example:
     * <pre>
     *   className="com.macmario.catalina.valves.AccessLogValve"
     *   →  className="org.apache.catalina.valves.AccessLogValve"
     * </pre>
     *
     * @return {@code true} when at least one class name was restored and the file was written
     */
    boolean uninstall() {
        boolean b=true;
        if (b) b=replaceClasses("com.macmario.", "uninstall");
        if (b) b=replacePassword(false);
        return b;
    }
    
    /**
     * Encrypts (crypt=true) or decrypts (crypt=false) {@code password} and {@code username}
     * attribute values found in {@code <Connector>} and {@code <Resource>} (DataSource) elements.
     *
     * <p>Encryption uses {@link TomcatPasswordCrypt} (AES-256-GCM). Already-encrypted values
     * (detected via {@link TomcatPasswordCrypt#isEncrypted}) are skipped on encrypt, and
     * plaintext values are skipped on decrypt, so the operation is idempotent.
     *
     * <p>The raw file text is read, modified, and written back — all comments and formatting
     * are preserved exactly.
     *
     * @param crypt {@code true} to encrypt plaintext values; {@code false} to decrypt
     * @return {@code true} when at least one credential was processed and the file was written
     */
    boolean replacePassword(boolean crypt) {
        if (isNullOrEmpty(rf)) { log(1, "replacePassword: no server.xml"); return false; }
        try {
            java.nio.file.Path filePath = rf.getFile().toPath();
            String content = Files.readString(filePath, StandardCharsets.UTF_8);
            TomcatPasswordCrypt tp = TomcatPasswordCrypt.getInstance(null);

            // Match password= and username= attributes anywhere in server.xml.
            // In a Tomcat server.xml these only appear in <Connector> and <Resource> elements.
            Pattern p = Pattern.compile(
                    "(\\b(?:password|username)\\s*=\\s*[\"'])([^\"']*?)([\"'])",
                    Pattern.DOTALL);
            Matcher m = p.matcher(content);
            StringBuffer sb = new StringBuffer();
            int count = 0;

            while (m.find()) {
                String attrPrefix = m.group(1); // e.g. password="
                String original   = m.group(2);
                String attrSuffix = m.group(3);

                String processed;
                if (crypt) {
                    if (original.isEmpty() || TomcatPasswordCrypt.isEncrypted(original)) {
                        m.appendReplacement(sb, Matcher.quoteReplacement(m.group(0)));
                        continue;
                    }
                    processed = tp.encrypt(original);
                } else {
                    if (!TomcatPasswordCrypt.isEncrypted(original)) {
                        m.appendReplacement(sb, Matcher.quoteReplacement(m.group(0)));
                        continue;
                    }
                    processed = tp.decrypt(original);
                }

                m.appendReplacement(sb, Matcher.quoteReplacement(attrPrefix + processed + attrSuffix));
                String key = attrPrefix.split("[\\s=]")[0]; // "password" or "username"
                log(1, "replacePassword(" + crypt + "): " + key + " processed");
                count++;
            }
            m.appendTail(sb);

            if (count == 0) { log(1, "replacePassword: nothing to process — file not written"); return true; }
            Files.writeString(filePath, sb.toString(), StandardCharsets.UTF_8);
            log(1, "replacePassword: " + count + " credential(s) updated → " + filePath);
            return true;
        } catch (IOException e) {
            log(1, "replacePassword: FAILED — " + e.getMessage());
            return false;
        }
    }

    /**
     * Applies {@link #getReplacedClass} to every {@code className}, {@code protocol},
     * {@code factory}, and {@code type} attribute value that starts with {@code fromPrefix}.
     * Reads the raw file text, replaces all matching occurrences, and writes it back so that
     * comments and formatting are never touched.
     */
    private boolean replaceClasses(String fromPrefix, String label) {
        if (isNullOrEmpty(rf)) { log(1, label + ": no server.xml"); return false; }
        try {
            java.nio.file.Path filePath = rf.getFile().toPath();
            String content = Files.readString(filePath, StandardCharsets.UTF_8);

            // Match className=, protocol=, factory=, type= attribute values only.
            Pattern p = Pattern.compile(
                    "((?:className|protocol|factory|type)\\s*=\\s*[\"'])([\\w.]+)([\"'])",
                    Pattern.DOTALL);
            Matcher m = p.matcher(content);
            StringBuffer sb = new StringBuffer();
            int count = 0;
            while (m.find()) {
                String original = m.group(2);
                if (!original.startsWith(fromPrefix)) {
                    m.appendReplacement(sb, Matcher.quoteReplacement(m.group(1) + original + m.group(3)));
                    continue;
                }
                String replaced = getReplacedClass(original);
                if (replaced.equals(original)) {
                    // Not in the explicit map — leave unchanged
                    m.appendReplacement(sb, Matcher.quoteReplacement(m.group(1) + original + m.group(3)));
                    continue;
                }
                m.appendReplacement(sb, Matcher.quoteReplacement(m.group(1) + replaced + m.group(3)));
                log(1, label + ": " + original + " → " + replaced);
                count++;
            }
            m.appendTail(sb);

            if (count == 0) { log(1, label + ": no substitutions — file not written"); return false; }
            Files.writeString(filePath, sb.toString(), StandardCharsets.UTF_8);
            log(1, label + ": " + count + " class(es) updated → " + filePath);
            return true;
        } catch (IOException e) {
            log(1, label + ": FAILED — " + e.getMessage());
            return false;
        }
    }

    /**
     * Applies key=value update directives from {@code ar[j..]} and persists the result.
     *
     * <p>Supported directives:
     * <ul>
     *   <li>{@code adminport=<port>}  — {@code <Server port="…">} shutdown port.</li>
     *   <li>{@code httpport=<port>}   — HTTP  {@code <Connector port="…">}.</li>
     *   <li>{@code httpsport=<port>}  — HTTPS {@code <Connector port="…">} (SSLEnabled).</li>
     *   <li>{@code ajpport=<port>}    — AJP   {@code <Connector port="…">}.</li>
     * </ul>
     */
    boolean update(String[] ar, int j) {
        log(1, "update start");
        if (isNullOrEmpty(rf) || isNullOrEmpty(doc)) return false;

        boolean changed = false;
        log(1, "update verify tasks");
        for (int i = j; i < ar.length; i++) {
            if (ar[i].startsWith("adminport=")) {
                if (updateAdminPort(getInt(ar[i].substring("adminport=".length())))) changed = true;
            } else if (ar[i].startsWith("httpport=")) {
                if (updatePort(getInt(ar[i].substring("httpport=".length()))))      changed = true;
            } else if (ar[i].startsWith("httpsport=")) {
                if (updateSSLPort(getInt(ar[i].substring("httpsport=".length()))))  changed = true;
            } else if (ar[i].startsWith("ajpport=")) {
                if (updateAJPPort(getInt(ar[i].substring("ajpport=".length()))))    changed = true;
            }
        }

        boolean saved = changed && updateServerXML();
        log(1, "update end " + saved);
        return saved;
    }

    /**
     * Sets the {@code port} attribute on the root {@code <Server>} element.
     *
     * <pre>  {@code <Server port="18005" shutdown="SHUTDOWN">}
     *   →  {@code <Server port="17005" shutdown="SHUTDOWN">}</pre>
     *
     * @param po new admin/shutdown port (1–65535)
     * @return {@code true} when the attribute was updated in the DOM
     */
    private boolean updateAdminPort(int po) {
        if (!isPort(po)) {
            log(1, "updateAdminPort: invalid port " + po);
            return false;
        }
        log(1, "updateAdminPort: setting port=" + po);
        doc.getDocumentElement().setAttribute("port", String.valueOf(po));
        return true;
    }

    /**
     * Sets the {@code port} attribute on the HTTP {@code <Connector>} element.
     *
     * <p>Selects the first {@code <Connector>} that is neither AJP nor SSL:
     * protocol does not contain {@code "AJP"} and {@code SSLEnabled} is not {@code "true"}.
     *
     * <pre>  {@code <Connector port="18080" protocol="HTTP/1.1" …>}
     *   →  {@code <Connector port="17080" protocol="HTTP/1.1" …>}</pre>
     *
     * @param po new HTTP connector port (1–65535)
     * @return {@code true} when an HTTP connector was found and updated
     */
    private boolean updatePort(int po) {
        if (!isPort(po)) { log(1, "updatePort: invalid port " + po); return false; }
        NodeList connectors = doc.getElementsByTagName("Connector");
        for (int idx = 0; idx < connectors.getLength(); idx++) {
            Element conn = (Element) connectors.item(idx);
            if (isAjpConnector(conn) || isSslConnector(conn)) continue;
            int old = getInt(conn.getAttribute("port"));
            if (!isPort(old)) continue;
            httpPortOld = old;
            httpPortNew = po;
            conn.setAttribute("port", String.valueOf(po));
            log(1, "updatePort: HTTP Connector " + httpPortOld + " → " + httpPortNew);
            return true;
        }
        log(1, "updatePort: no HTTP Connector found");
        return false;
    }

    /**
     * Sets the {@code port} attribute on the HTTPS (SSL) {@code <Connector>} element.
     *
     * <p>Selects the first {@code <Connector>} with {@code SSLEnabled="true"} or
     * {@code scheme="https"}.
     *
     * <pre>  {@code <Connector port="8443" SSLEnabled="true" …>}
     *   →  {@code <Connector port="7443" SSLEnabled="true" …>}</pre>
     *
     * @param po new HTTPS connector port (1–65535)
     * @return {@code true} when an SSL connector was found and updated
     */
    private boolean updateSSLPort(int po) {
        if (!isPort(po)) { log(1, "updateSSLPort: invalid port " + po); return false; }
        NodeList connectors = doc.getElementsByTagName("Connector");
        for (int idx = 0; idx < connectors.getLength(); idx++) {
            Element conn = (Element) connectors.item(idx);
            if (!isSslConnector(conn)) continue;
            int old = getInt(conn.getAttribute("port"));
            if (!isPort(old)) continue;
            sslPortOld = old;
            sslPortNew = po;
            conn.setAttribute("port", String.valueOf(po));
            log(1, "updateSSLPort: HTTPS Connector " + sslPortOld + " → " + sslPortNew);
            return true;
        }
        log(1, "updateSSLPort: no HTTPS Connector found");
        return false;
    }

    /**
     * Sets the {@code port} attribute on the AJP {@code <Connector>} element.
     *
     * <p>Selects the first {@code <Connector>} whose {@code protocol} attribute
     * contains {@code "AJP"} (case-insensitive).
     *
     * <pre>  {@code <Connector protocol="AJP/1.3" port="18009" …>}
     *   →  {@code <Connector protocol="AJP/1.3" port="17009" …>}</pre>
     *
     * @param po new AJP connector port (1–65535)
     * @return {@code true} when an AJP connector was found and updated
     */
    private boolean updateAJPPort(int po) {
        if (!isPort(po)) { log(1, "updateAJPPort: invalid port " + po); return false; }
        NodeList connectors = doc.getElementsByTagName("Connector");
        for (int idx = 0; idx < connectors.getLength(); idx++) {
            Element conn = (Element) connectors.item(idx);
            if (!isAjpConnector(conn)) continue;
            int old = getInt(conn.getAttribute("port"));
            if (!isPort(old)) continue;
            ajpPortOld = old;
            ajpPortNew = po;
            conn.setAttribute("port", String.valueOf(po));
            log(1, "updateAJPPort: AJP Connector " + ajpPortOld + " → " + ajpPortNew);
            return true;
        }
        log(1, "updateAJPPort: no AJP Connector found");
        return false;
    }

    // ── Connector type helpers ──────────────────────────────────────────────────

    private static boolean isAjpConnector(Element conn) {
        return conn.getAttribute("protocol").toUpperCase().contains("AJP");
    }

    private static boolean isSslConnector(Element conn) {
        return "true".equalsIgnoreCase(conn.getAttribute("SSLEnabled"))
                || "https".equalsIgnoreCase(conn.getAttribute("scheme"));
    }

    /**
     * Persists all pending DOM changes back to the original {@code server.xml}
     * file using targeted text substitutions.
     *
     * <p>Each substitution replaces exactly one attribute value in the raw file
     * text, so every comment block, blank line, and whitespace character is
     * preserved as-is.
     *
     * <p>Substitutions applied (only when the corresponding update method ran):
     * <ul>
     *   <li>{@code <Server port="…">}         — {@link #updateAdminPort}</li>
     *   <li>{@code <Connector port="…">} HTTP  — {@link #updatePort}</li>
     *   <li>{@code <Connector port="…">} HTTPS — {@link #updateSSLPort}</li>
     *   <li>{@code <Connector port="…">} AJP   — {@link #updateAJPPort}</li>
     * </ul>
     * <p>Each substitution anchors on the exact old-port value recorded before the
     * DOM was modified, so connectors with different port numbers are never touched.
     *
     * @return {@code true} when at least one substitution succeeded and the file
     *         was written; {@code false} on no-change or any I/O error
     */
    public boolean updateServerXML() {
        if (isNullOrEmpty(rf) || isNullOrEmpty(doc)) return false;
        try {
            java.nio.file.Path filePath = rf.getFile().toPath();
            String content = Files.readString(filePath, StandardCharsets.UTF_8);
            String updated = content;
            boolean anyChange = false;

            // ── <Server port="…"> ────────────────────────────────────────────
            // Root element — always present; DOTALL handles multi-line opening tags.
            String newAdminPort = doc.getDocumentElement().getAttribute("port");
            Matcher mServer = Pattern.compile(
                    "(<Server\\b[^>]*?\\bport\\s*=\\s*[\"'])([^\"']*?)([\"'])",
                    Pattern.DOTALL).matcher(updated);
            if (mServer.find()) {
                updated = mServer.replaceFirst(
                        "$1" + Matcher.quoteReplacement(newAdminPort) + "$3");
                anyChange = true;
            } else {
                log(1, "updateServerXML: <Server port=…> not found in file text");
            }

            // ── <Connector port="…"> (HTTP) ──────────────────────────────────
            if (httpPortOld > 0 && httpPortNew > 0) {
                Matcher mConn = Pattern.compile(
                        "(<Connector\\b[^>]*?\\bport\\s*=\\s*[\"'])"
                        + httpPortOld + "([\"'])",
                        Pattern.DOTALL).matcher(updated);
                if (mConn.find()) {
                    updated = mConn.replaceFirst(
                            "$1" + Matcher.quoteReplacement(String.valueOf(httpPortNew)) + "$2");
                    anyChange = true;
                } else {
                    log(1, "updateServerXML: HTTP Connector port=" + httpPortOld + " not found");
                }
            }

            // ── <Connector port="…"> (HTTPS / SSL) ───────────────────────────
            if (sslPortOld > 0 && sslPortNew > 0) {
                Matcher mSsl = Pattern.compile(
                        "(<Connector\\b[^>]*?\\bport\\s*=\\s*[\"'])"
                        + sslPortOld + "([\"'])",
                        Pattern.DOTALL).matcher(updated);
                if (mSsl.find()) {
                    updated = mSsl.replaceFirst(
                            "$1" + Matcher.quoteReplacement(String.valueOf(sslPortNew)) + "$2");
                    anyChange = true;
                } else {
                    log(1, "updateServerXML: HTTPS Connector port=" + sslPortOld + " not found");
                }
            }

            // ── <Connector port="…"> (AJP) ───────────────────────────────────
            if (ajpPortOld > 0 && ajpPortNew > 0) {
                Matcher mAjp = Pattern.compile(
                        "(<Connector\\b[^>]*?\\bport\\s*=\\s*[\"'])"
                        + ajpPortOld + "([\"'])",
                        Pattern.DOTALL).matcher(updated);
                if (mAjp.find()) {
                    updated = mAjp.replaceFirst(
                            "$1" + Matcher.quoteReplacement(String.valueOf(ajpPortNew)) + "$2");
                    anyChange = true;
                } else {
                    log(1, "updateServerXML: AJP Connector port=" + ajpPortOld + " not found");
                }
            }

            if (!anyChange) {
                log(1, "updateServerXML: no substitutions applied — file not written");
                return false;
            }
            Files.writeString(filePath, updated, StandardCharsets.UTF_8);
            log(1, "updateServerXML: saved → " + filePath);
            return true;
        } catch (IOException e) {
            log(1, "updateServerXML: FAILED — " + e.getMessage());
            return false;
        }
    }

    // ── Internal helpers ────────────────────────────────────────────────────────

    private ReadFile findServerXml(String info) {
        final String file = "server.xml";
        ReadFile tf = new ReadFile(info);
        if (tf.isReadableFile() && tf.getFileName().endsWith(file)) {
            log(1, "findServerXML: found direct");
            return tf;
        }
        if (tf.isReadableDirectory()) {
            tf = new ReadFile(info + _FS + file);
            if (tf.isReadableFile()) {
                log(1, "findServerXML: dir — found direct");
                return tf;
            }
            tf = new ReadFile(info + _FS + "conf" + _FS + file);
            if (tf.isReadableFile()) {
                log(1, "findServerXML: dir — found from CATALINA_BASE/conf");
                return tf;
            }
        }
        // Fallback: working directory — allows omitting the path when running from
        // the directory that contains server.xml or a conf/ sub-directory.
        String cwd = System.getProperty("user.dir");
        tf = new ReadFile(cwd + _FS + file);
        if (tf.isReadableFile()) {
            log(1, "findServerXML: found in working dir");
            return tf;
        }
        tf = new ReadFile(cwd + _FS + "conf" + _FS + file);
        if (tf.isReadableFile()) {
            log(1, "findServerXML: found in working dir/conf");
            return tf;
        }
        log(1, "findServerXML: NULL — no server.xml found at: " + info);
        return null;
    }

    private boolean readServerXml() {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            doc = db.parse(rf.getFile());
            doc.getDocumentElement().normalize();
            return true;
        } catch (IOException | SAXException | ParserConfigurationException e) {
            log(1, "readServerXml: FAILED — " + e.getMessage());
            return false;
        }
    }

    private boolean isPort(int po) {
        return (po > 0 && po < 64 * 1024);
    }

    private boolean isPrivPort(int po) {
        return (po > 0 && po < 1024);
    }
    
    /**
     * Returns the class-name counterpart for the given fully-qualified class name.
     *
     * <p>Explicit bidirectional mapping:
     * <ul>
     *   <li>{@code org.apache.coyote.http11.Http11NioProtocol}  ↔ {@code com.macmario.services.coyote.CustomHttp11NioProtocol}</li>
     *   <li>{@code org.apache.coyote.http11.Http11Nio2Protocol} ↔ {@code com.macmario.services.coyote.CustomHttp2NioProtocol}</li>
     *   <li>{@code org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory} ↔ {@code com.macmario.services.coyote.EncryptedDataSourceFactory}</li>
     * </ul>
     * Any class name not in the map is returned unchanged.
     *
     * @param clname fully-qualified class name (may be {@code null} or blank)
     * @return the mapped counterpart, or {@code clname} when no mapping exists
     */
    static String getReplacedClass(String clname) {
        if (clname == null || clname.isEmpty()) return clname;
        switch (clname) {
            case "org.apache.coyote.http11.Http11NioProtocol": 
                  return "com.macmario.services.coyote.CustomHttp11NioProtocol";
            case "com.macmario.services.coyote.CustomHttp11NioProtocol":
                  return "org.apache.coyote.http11.Http11NioProtocol";
            case "org.apache.coyote.http11.Http11Nio2Protocol":
                  return "com.macmario.services.coyote.CustomHttp2NioProtocol";
            case "com.macmario.services.coyote.CustomHttp2NioProtocol" :
                   return "org.apache.coyote.http11.Http11Nio2Protocol";
            case "org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory":
                   return "com.macmario.services.coyote.EncryptedDataSourceFactory";
            case "com.macmario.services.coyote.EncryptedDataSourceFactory":
                   return "org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory";
            default: { break; }       
        }
        
        return clname;
    }
    
}
