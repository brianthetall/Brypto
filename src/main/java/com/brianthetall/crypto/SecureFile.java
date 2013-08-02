package com.brianthetall.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.lang.String;
import java.lang.Exception;
import com.brianthetall.crypto.AES;
import com.brianthetall.crypto.AES.Credential;

public class SecureFile{

    //    private FileInputStream input=null;
    private FileOutputStream output=null;
    private AES aes=null;

    public SecureFile(){
	try{
	    aes = new AES();
	}catch(Exception e){
	    System.out.println("SecureFile: Error creating AES object");
	}
    }

    public byte[] encrypt(byte[] input){
	if(input==null)
	    return null;
	else if(input.length==0)
	    return null;
	byte[] retval=null;
	try{
	    retval=aes.encrypt(input);
	}catch(Exception e){
	    System.out.println("SecureFile.encrypt(byte[])");
	}
	return retval;
    }

    public File encrypt(File input){
	File retval=null;
	if(input==null||aes==null)
	    return null;
	try{
	    retval = aes.encrypt(input);
	}catch(Exception e){
	    System.out.println("SecureFile.encrypt");
	}
	return retval;
    }

    public byte[] decrypt(byte[] input,byte[] key,byte[] iv){
	if(input==null)
	    return null;
	else if(input.length==0)
	    return null;

	if(key!=null)
	    getCreds().setKey(key);
	if(iv!=null)
	    getCreds().setIV(iv);

	try{
	    return aes.decrypt(input);
	}catch(Exception e){
	    System.err.println(e.getMessage());
	}
	return null;
    }

    public File decrypt(File input){
	File retval=null;
	if(input==null||aes==null)
	    return null;
	try{
	    retval = aes.decrypt(input);
	}catch(Exception e){
	    System.out.println("SecureFile.encrypt");
	}
	return retval;
    }

    public Credential getCreds(){
	return aes.getCreds();
    }

    public byte[] getKey(){
	return aes.getCreds().getKeyBytes();
    }

    public byte[] getIv(){
	return aes.getCreds().getIV();
    }

    /**
     *
     * @see AES.Credential
     */
    public void setCreds(byte[] key,byte[] iv){
	aes.getCreds().setIV(iv);
	aes.getCreds().setKey(key);
    }

    public static void main(String args[]){
	if(args.length!=1)
	    System.out.println("Wrong number of args");
	SecureFile sf = new SecureFile();
	sf.encrypt(new File(args[0]));
	sf.decrypt(new File(args[0].concat(".bri")));
    }
}
