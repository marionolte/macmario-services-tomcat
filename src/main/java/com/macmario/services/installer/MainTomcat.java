/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.macmario.services.installer;

import com.macmario.general.Version;
import com.macmario.services.coyote.TomcatPasswordCrypt;

/**
 *
 * @author SuMario
 */
public class MainTomcat extends Version{
    
    
    public static void main(String[] args) {
        int use=0;
        TomcatPasswordCrypt tp=TomcatPasswordCrypt.getInstance(null);
    
        //System.out.println("MainTomcat");
        if ( args.length == 0 ) { use++; }
        else {
            for ( int i=0; i<args.length; i++ ) {
                if ( args[i].equals("-d") ) { debug++; }
            }
            for ( int i=0; i<args.length; i++ ) {
                if ( args[i].equals("-decrypt") && args.length>(i+1) ) { 
                       System.out.println(tp.decrypt(args[++i]));
                } 
                else if ( args[i].equals("-encrypt") && args.length>(i+1) ) { 
                       System.out.println(tp.encrypt(args[++i]));
                }
                else if ( args[i].equals("-cust") && args.length>(i+1) ) { 
                       tp = TomcatPasswordCrypt.getInstance(args[++i]);
                       
                } else if ( args[i].equals("-install") && args.length>(i+1) ) { 
                    
                   TomcatConfig tc = new TomcatConfig(args[++i]);
                                System.out.println( ((tc.install())?"Successfull":"Failed") );
                    
                } else if ( args[i].equals("-uninstall") && args.length>(i+1) ) {       
                    TomcatConfig tc = new TomcatConfig(args[++i]);
                                System.out.println( ((tc.uninstall())?"Successfull":"Failed") );
                    
                } else if ( args[i].equals("-update") && args.length>(i+1) ) { 
                    
                    TomcatConfig tc = new TomcatConfig(args[++i]);
                                System.out.println( ((tc.update(args,i))?"Successfull":"Failed") );
                    
                } else if ( args[i].equals("-d") ) {
                } else if ( args[i].contains("=") && !args[i].startsWith("-") ) {
                    // key=value directive consumed by a previous command (e.g. adminport=, httpport=)
                } else {
                    use++;
                }
            }
        }
        if ( use > 0 ) { usage(); System.exit(-1); } else { System.exit(0); }
    }
    
    private static void usage(){
        System.out.println("java -jar "+jarfile+" [-decrypt <STRING> | -encrypt <STRING>]");
    }
}
