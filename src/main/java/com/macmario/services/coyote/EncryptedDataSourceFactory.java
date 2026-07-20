package com.macmario.services.coyote;

import java.sql.SQLException;
import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.Name;
import javax.naming.RefAddr;
import javax.naming.Reference;
import javax.naming.StringRefAddr;

public class EncryptedDataSourceFactory extends org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory {

    @Override
    public Object getObjectInstance(Object obj, Name name, Context nameCtx,
                                    Hashtable<?, ?> environment) throws SQLException {
        TomcatPasswordCrypt tc = TomcatPasswordCrypt.getInstance(null);
        if (obj instanceof Reference ref) {
            decryptRefAddr(ref, "password", tc);
            decryptRefAddr(ref, "username", tc);
        }
        return super.getObjectInstance(obj, name, nameCtx, environment);
    }

    private static void decryptRefAddr(Reference ref, String addrType, TomcatPasswordCrypt tc) {
        for (int i = 0; i < ref.size(); i++) {
            RefAddr addr = ref.get(i);
            if (!addrType.equals(addr.getType())) continue;
            if (!(addr instanceof StringRefAddr sa)) break;
            String val = (String) sa.getContent();
            if (!TomcatPasswordCrypt.isEncrypted(val)) break;
            ref.remove(i);
            ref.add(i, new StringRefAddr(addrType, tc.decrypt(val)));
            break;
        }
    }
}
