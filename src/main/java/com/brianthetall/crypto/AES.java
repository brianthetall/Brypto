package com.brianthetall.crypto;

import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.File;
import javax.crypto.spec.IvParameterSpec;
import java.security.Security;
import java.security.SecureRandom;
import java.security.Key;
import java.security.AlgorithmParameters;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKey;
import javax.crypto.NoSuchPaddingException;
import java.security.spec.InvalidKeySpecException;
import java.security.NoSuchAlgorithmException;

public class AES{
    private static final int DEBUG=0;
    private byte[] output;
    private KeyGenerator keyGen;
    private Cipher cipher;
    private Credential creds;
    //private byte[] IV;
    //    private transient Key key;

    public class Credential{

	byte IV[];
	private transient Key key;

	public Credential(Key key){
	    this.key=key;
	}

	public Credential(Key key, byte IV[]){
	    this.key=key;
	    this.IV=IV;
	}

	public String toString(){
	    return (new String(key.getEncoded())+" "+new String(IV));
	}	

	public Key getKey(){
	    return key;
	}

	public byte[] getKeyBytes(){
	    return key.getEncoded();
	}	
	public byte[] getIV(){
	    return IV;
	}

	public void setKey(byte[] key){
	    try{
		SecretKeyFactory factory = SecretKeyFactory.getInstance("AES");
		SecretKey sk = factory.generateSecret(new SecretKeySpec(key,"AES"));
		this.key = sk;
	    }catch(Exception e){System.out.println("AES.Credential.setKey");}
				   
	}
	
	public void setIV(byte IV[]){
	    this.IV = IV;
	}
	
    }
    /*
      AES constructor called when using a pre-existing key & IV
     */
    public AES(byte[] key,byte[] IV){
	try{
	    SecretKeyFactory factory = SecretKeyFactory.getInstance("AES");
	    SecretKey secretKey = factory.generateSecret(new SecretKeySpec(key,"AES"));
	    creds = new Credential(secretKey,IV);
	    cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	}catch(NoSuchAlgorithmException e){System.out.println("AES: No such algorithm");}
	catch(InvalidKeySpecException e){System.out.println("AES: Invalid Key");}
	catch(NoSuchPaddingException e){System.out.println("AES: No such padding");}

    }
    
    public AES() throws Exception{
	keyGen = KeyGenerator.getInstance("AES");
	keyGen.init(128);
	creds = new Credential(keyGen.generateKey());
	if(DEBUG==1){System.out.println("Generated AES Key = "+new String(creds.getKey().getEncoded(),"UTF8") + "\r\nKey Algorithm="+creds.getKey().getAlgorithm());}
	cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    }

    public byte[] encrypt(byte[] plain)throws Exception{
	cipher.init(Cipher.ENCRYPT_MODE,creds.getKey());
	output = cipher.doFinal(plain);
	if(DEBUG==1){System.out.println("Cipher Text: " + new String(output,"UTF8"));}
	if(DEBUG==1){System.out.println("Cipher IV: "+new String(cipher.getIV(),"UTF8"));}
	//	IV = cipher.getIV();
	creds.setIV(cipher.getIV());
	return output;
    }

    public byte[] encrypt(String plainText) throws Exception{
	cipher.init(Cipher.ENCRYPT_MODE,creds.getKey());
	output = cipher.doFinal(plainText.getBytes());
	if(DEBUG==1){System.out.println("Cipher Text: " + new String(output,"UTF8"));}
	if(DEBUG==1){System.out.println("Cipher IV: "+new String(cipher.getIV(),"UTF8"));}
	//	IV = cipher.getIV();
	creds.setIV(cipher.getIV());
	return output;
    }

    public File encrypt(File plain){
	byte buffer[] = new byte[(int)plain.length()];
	byte cipherText[]=null;
	File retval=null;
	try{
	    //  cipher.init(Cipher.ENCRYPT_MODE,key);
	    cipher.init(Cipher.ENCRYPT_MODE,creds.getKey());
	}catch(Exception e){}
	try{
	    DataInputStream dis = new DataInputStream(new FileInputStream(plain));
	    dis.readFully(buffer);
	    dis.close();
	}catch(Exception e){
	    System.out.println("File encrypt(File) Error");
	}
	try{
	    cipherText = cipher.doFinal(buffer);
	}catch(Exception e){
	}
	try{
	    retval = new File(plain.getPath().concat(".bri"));
	    FileOutputStream fos = new FileOutputStream(retval);
	    fos.write(cipherText);
	    fos.flush();
	    fos.close();
	}catch(Exception e){

	}
	//	IV = cipher.getIV();
	creds.setIV(cipher.getIV());
	return retval;
    }


    public byte[] decrypt(byte[] cipherText) throws Exception{
	//	cipher.init(Cipher.DECRYPT_MODE,key,new IvParameterSpec(IV));
	cipher.init(Cipher.DECRYPT_MODE,creds.getKey(),new IvParameterSpec(creds.getIV()));
	output = cipher.doFinal(cipherText);
	if(DEBUG==1){System.out.println("Plain Text: " + new String(output));}
	return output;
	//zero key[]
    }

    public File decrypt(File cipherText){
	byte buffer[] = new byte[(int)cipherText.length()];
	byte plain[]=null;
	File retval=null;
	try{
	    //	    cipher.init(Cipher.DECRYPT_MODE,key,new IvParameterSpec(IV));
	    cipher.init(Cipher.DECRYPT_MODE,creds.getKey(),new IvParameterSpec(creds.getIV()));
	}catch(Exception e){}
	try{
	    DataInputStream dis = new DataInputStream(new FileInputStream(cipherText));
	    dis.readFully(buffer);
	    dis.close();
	}catch(Exception e){
	    System.out.println("File decrypt(File) Error");
	}
	try{
	    plain = cipher.doFinal(buffer);
	}catch(Exception e){
	}
	try{
	    retval = new File(cipherText.getPath().concat(".plain"));
	    FileOutputStream fos = new FileOutputStream(retval);
	    fos.write(plain);
	    fos.flush();
	    fos.close();
	}catch(Exception e){

	}
	creds.setIV(cipher.getIV());
	return retval;
    }

    /*
      to be run after an encrypt to get the key/IV used
     */
    public Credential getCreds(){
	return creds;
    }

    public static void main(String args[]) throws Exception{
	if(args.length!=1)
	    System.exit(-1);
	AES crypt = new AES();
	if(args[0].equals(new String(crypt.decrypt(crypt.encrypt(args[0])))))
	    System.out.println("Class: JavaAES is working!");
    }
}
