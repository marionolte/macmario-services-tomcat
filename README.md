# MHService Tomcat — Infrastructure Config Manager

A standalone CLI tool for managing Tomcat `server.xml` without touching the files manually.
It handles three concerns in one JAR:

- **Port updates** — change shutdown, HTTP, HTTPS, and AJP ports
- **Install / uninstall** — swap Tomcat's built-in class names for custom `com.macmario` equivalents (and back), and encrypt/decrypt credentials in the same step
- **Password encryption** — AES-256-GCM symmetric encryption for passwords stored in `server.xml`

---

## Build

Requires Java 17 and Maven.

```shell
cd tools/tomcat
mvn package -DskipTests
# produces: target/MHService-tomcat-1.0.jar
```

---

## CLI usage

```
java -jar MHService-tomcat-1.0.jar <command> [args...]
```

### Encrypt / decrypt a string

```shell
# Encrypt
java -jar MHService-tomcat-1.0.jar -encrypt mySecretPassword
# → {SHA}hZr+h1BI3wjQpCg...

# Decrypt
java -jar MHService-tomcat-1.0.jar -decrypt "{SHA}hZr+h1BI3wjQpCg..."
# → mySecretPassword

# Use a custom passphrase instead of the built-in key
java -jar MHService-tomcat-1.0.jar -cust myPassphrase -encrypt mySecretPassword
```

### Update ports in server.xml

The path argument can be a direct path to `server.xml`, a directory containing
`server.xml`, or a `CATALINA_BASE` directory (tool looks inside `conf/server.xml`).
If the path is omitted the current working directory is searched.

```shell
# Single port
java -jar MHService-tomcat-1.0.jar -update /opt/tomcat adminport=17005
java -jar MHService-tomcat-1.0.jar -update /opt/tomcat httpport=17080
java -jar MHService-tomcat-1.0.jar -update /opt/tomcat httpsport=17443
java -jar MHService-tomcat-1.0.jar -update /opt/tomcat ajpport=17009

# Multiple ports in one pass
java -jar MHService-tomcat-1.0.jar -update /opt/tomcat \
    adminport=17005 httpport=17080 httpsport=17443 ajpport=17009
```

| Directive | XML element modified |
|---|---|
| `adminport=<n>` | `<Server port="…">` (shutdown listener) |
| `httpport=<n>` | First `<Connector>` that is not AJP and not SSL |
| `httpsport=<n>` | `<Connector SSLEnabled="true">` or `scheme="https"` |
| `ajpport=<n>` | `<Connector protocol="AJP/…">` |

All comments, whitespace, and unrelated attributes are preserved exactly —
the tool uses targeted text substitution anchored on the old port value, not DOM serialisation.

### Install custom classes and encrypt credentials

```shell
java -jar MHService-tomcat-1.0.jar -install /opt/tomcat
```

Two steps happen in order:

1. **Class replacement** — Tomcat's built-in `protocol=`, `className=`, `factory=`, and `type=`
   attribute values are replaced with `com.macmario` equivalents (see table below).
2. **Credential encryption** — every `password=` and `username=` attribute in
   `<Connector>` and `<Resource>` elements is encrypted with AES-256-GCM.
   Values already carrying the `{SHA}` prefix are skipped.

### Uninstall (restore original classes and decrypt credentials)

```shell
java -jar MHService-tomcat-1.0.jar -uninstall /opt/tomcat
```

Reverses both steps: restores `org.apache` class names and decrypts `{SHA}…` credential values.

---

## Class replacement map

`-install` replaces the left column with the right; `-uninstall` reverses.

| Tomcat built-in (`org.apache`) | Custom (`com.macmario`) |
|---|---|
| `coyote.http11.Http11NioProtocol` | `services.coyote.CustomHttp11NioProtocol` |
| `coyote.http11.Http11Nio2Protocol` | `services.coyote.CustomHttp2NioProtocol` |
| `tomcat.dbcp.dbcp2.BasicDataSourceFactory` | `services.coyote.EncryptedDataSourceFactory` |

Only these three mappings are applied; all other class names (Listeners, Realms, Valves, etc.)
are left unchanged.

---

## Runtime classes

These classes must be on Tomcat's class path (e.g. placed in `$CATALINA_HOME/lib`)
after `-install` so Tomcat can load them at startup.

### `CustomHttp11NioProtocol` / `CustomHttp2NioProtocol`

Extend `Http11NioProtocol` and `Http11Nio2Protocol` respectively.
Override `addSslHostConfig` to decrypt the keystore password before Tomcat
opens the SSL socket — so `server.xml` can store an encrypted `certificateKeystorePassword`.

```xml
<!-- server.xml after -install -->
<Connector protocol="com.macmario.services.coyote.CustomHttp11NioProtocol"
           port="18443" SSLEnabled="true" ...>
  <SSLHostConfig>
    <Certificate certificateKeystoreFile="conf/keystore.jks"
                 certificateKeystorePassword="{SHA}..." />
  </SSLHostConfig>
</Connector>
```

### `EncryptedDataSourceFactory`

Extends `BasicDataSourceFactory` (Tomcat DBCP2).
Intercepts the JNDI `Reference` entries for `password` and `username`
**before** the parent factory reads them, decrypts any `{SHA}…` value, and
then lets the standard factory build the connection pool with the plain-text credentials.
`BasicDataSource.getPassword()` is never called, avoiding the deprecated post-init getter.

```xml
<!-- server.xml after -install -->
<Resource name="jdbc/appDB"
          factory="com.macmario.services.coyote.EncryptedDataSourceFactory"
          type="javax.sql.DataSource"
          username="{SHA}..."
          password="{SHA}..."
          ... />
```

---

## Encryption details

`TomcatPasswordCrypt` uses **AES-256-GCM** with standard JDK only (no external libraries):

- The 256-bit AES key is derived from a passphrase via **SHA-256**.
- A fresh **12-byte random IV** is generated for every `encrypt()` call, so identical
  plaintexts produce different ciphertexts.
- Wire format: `{SHA}` prefix + Base64(`IV[12]` ‖ `ciphertext+GCM-tag[n+16]`).
- The default passphrase is resolved from the bundled `coyote.properties` resource
  (`UKEY` property). Override with `-cust <passphrase>` on the CLI.

---

## Sample

A reference `server.xml` covering all four port types and a JDBC DataSource is provided at:

```
sample/conf/server.xml
```

Use it to test the tool from the `sample/` directory:

```shell
cd sample
java -jar ../target/MHService-tomcat-1.0.jar -install <conf>
java -jar ../target/MHService-tomcat-1.0.jar -update  <conf> adminport=17005 httpport=17080 httpsport=17443 ajpport=17009
java -jar ../target/MHService-tomcat-1.0.jar -uninstall <conf>
```
