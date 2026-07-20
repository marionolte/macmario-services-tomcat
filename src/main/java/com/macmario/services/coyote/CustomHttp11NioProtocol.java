/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.macmario.services.coyote;

import org.apache.tomcat.util.net.SSLHostConfig;

/**
 *
 * @author Sumario
 */
public class CustomHttp11NioProtocol extends org.apache.coyote.http11.Http11NioProtocol {
    
    @Override
    public void addSslHostConfig(SSLHostConfig conf) {
       conf.getCertificates().stream().forEach(a -> a.setCertificateKeystorePassword(
                   TomcatPasswordCrypt.getInstance(null).decrypt(a.getCertificateKeystorePassword())));
    
            super.addSslHostConfig(conf);
    }
}
