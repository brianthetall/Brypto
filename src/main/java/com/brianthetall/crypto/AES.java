package com.brianthetall.crypto;

import java.lang.Exception;
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
    private Cipher cipher;
    private Credential creds;

    /**
     * Determine if two AES objects are equal
     * @return true if the Credential of the objects match; else false
     */
    @Override public boolean equals(Object o){
	if(o==null)
	    return false;
	AES test=(AES)o;
	if(creds.equals(test.getCreds())){
	    return true;
	}
	return false;
    }

    public static class Credential{

	byte IV[];
	private transient Key key;

	/**
	 * @param key assign this key to this new Credential
	 */
	public Credential(Key key){
	    this.key=key;
	}

	/**
	 * Construct a Credential with Key and IV; useful for decryption
	 * @param key assign this key to this new Credential
	 * @param IV byte array containing IV
	 */
	public Credential(Key key, byte IV[]){
	    this.key=key;
	    this.IV=IV;
	}

	/**
	 * Equals method for AES.Credential
	 * @return true if Key and IV match
	 */
	@Override public boolean equals(Object o){
	    if(o!=null){
		Credential c=(Credential)o;
		if(key.equals(c.getKey())){

		    byte[] cIV=c.getIV();
		    if(cIV.length!=IV.length)
			return false;
		    for(int i=0;i<cIV.length;i++){
			if(cIV[i] != IV[i])
			    return false;
		    }

		    return true;
		}
	    }
	    return false;
	}

	/**
	 * @return String of Key and IV
	 */
	@Override public String toString(){
	    return (new String(key.getEncoded())+" "+new String(IV));
	}	

	/**
	 * Getter for Key
	 * @return Key for this Credential
	 */
	public Key getKey(){
	    return key;
	}

	/**
	 * Getter for Key
	 * @return Key in byte[] form
	 */
	public byte[] getKeyBytes(){
	    return key.getEncoded();
	}

	/**
	 * Getter for IV
	 */
	public byte[] getIV(){
	    return IV;
	}

	/**
	 * Set this Credential's Key
	 * @param key to assign
	 */
	public void setKey(byte[] key){
	    try{
		SecretKeyFactory factory = SecretKeyFactory.getInstance("AES");
		SecretKey sk = factory.generateSecret(new SecretKeySpec(key,"AES"));
		this.key = sk;
	    }catch(Exception e){System.out.println("AES.Credential.setKey");}
				   
	}

	/**
	 * Set this Credential's IV
	 * @param IV to assign
	 */	
	public void setIV(byte IV[]){
	    this.IV = IV;
	}
	
    }

    /**
     * AES contructs with known key and IV; useful for decrypting
     * @param key AES key byte array
     * @param IV for AES
     */
    public AES(byte[] key,byte[] IV)throws Exception{

	if(key==null)
	    throw new Exception("Invalid AES-key input");
	else if(key.length==0)
	    throw new Exception("Invalid AES-key input");

	try{
	    SecretKeyFactory factory = SecretKeyFactory.getInstance("AES");
	    SecretKey secretKey = factory.generateSecret(new SecretKeySpec(key,"AES"));
	    creds = new Credential(secretKey,IV);
	    cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	}catch(NoSuchAlgorithmException e){System.out.println("AES: No such algorithm");}
	catch(InvalidKeySpecException e){System.out.println("AES: Invalid Key");}
	catch(NoSuchPaddingException e){System.out.println("AES: No such padding");}

    }
    
    /**
     * Construct an AES object; a key is generated and stored in an AES.Credential.
     * @throws Exception
     * @see AES.Credential
     */
    public AES() throws Exception{
	KeyGenerator keyGen = KeyGenerator.getInstance("AES");
	keyGen.init(128);
	creds = new Credential(keyGen.generateKey());

	if(DEBUG==1){System.out.println("Generated AES Key = "+new String(creds.getKey().getEncoded(),"UTF8") + "\r\nKey Algorithm="+creds.getKey().getAlgorithm());}
	
	cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    }

    /**
     * Encrypt a byte array; return cipher[]. The resulting IV is stored in this-object's AES.Credential.
     * @param plain byte[]
     * @return encrypted byte[]
     * @see AES.Credential
     */
    public byte[] encrypt(byte[] plain)throws Exception{
	cipher.init(Cipher.ENCRYPT_MODE,creds.getKey());
	byte[] output = cipher.doFinal(plain);
	if(DEBUG==1){System.out.println("Cipher Text: " + new String(output,"UTF8"));}
	if(DEBUG==1){System.out.println("Cipher IV: "+new String(cipher.getIV(),"UTF8"));}

	creds.setIV(cipher.getIV());
	return output;
    }

    /**
     * Encrypt a String. Store resulting IV in this object's AES.Credential
     * @param plainText
     * @return cipherText byte[]
     * @see AES.Credential
     */
    public byte[] encrypt(String plainText) throws Exception{
	cipher.init(Cipher.ENCRYPT_MODE,creds.getKey());
	byte[] output = cipher.doFinal(plainText.getBytes());
	if(DEBUG==1){System.out.println("Cipher Text: " + new String(output,"UTF8"));}
	if(DEBUG==1){System.out.println("Cipher IV: "+new String(cipher.getIV(),"UTF8"));}
	creds.setIV(cipher.getIV());
	return output;
    }

    /**
     * Encrypt java.io.File and store resulting file in same directory.
     * @param plain File to encrypt
     * @return encrypted File reference
     */
    public File encrypt(File plain){
	byte buffer[] = new byte[(int)plain.length()];
	byte cipherText[]=null;
	File retval=null;
	try{
	    cipher.init(Cipher.ENCRYPT_MODE,creds.getKey());
	}catch(Exception e){
	    System.out.println("AES.encrypt init:"+e.getMessage());
	}
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
	    System.err.println("AES.encrypt ERROR:"+e.getMessage());
	}
	creds.setIV(cipher.getIV());
	return retval;
    }


    /**
     * Decrypt a byte[]. AES-credential must be configured first!
     * @param cipherText
     * @return byte[] containing plain-text. Null if input is invalid.
     * @see AES.Credential
     */
    public byte[] decrypt(byte[] cipherText) throws Exception{

	if(cipherText==null || cipherText.length==0)
	    return null;

	cipher.init(Cipher.DECRYPT_MODE,creds.getKey(),new IvParameterSpec(creds.getIV()));
	byte[] output = cipher.doFinal(cipherText);
	if(DEBUG==1){System.out.println("Plain Text: " + new String(output));}
	return output;
	//zero key[]
    }

    /**
     * Decrypts a java.io.File. This AES's credentials must be set with a key AND IV!
     * @param cipherText contains cipher-text; plain-file will be written to this folder
     * @return a reference to a File containing plain-text
     * @see AES.Credential
     */
    public File decrypt(File cipherText){
	byte buffer[] = new byte[(int)cipherText.length()];
	byte plain[]=null;
	File retval=null;
	try{
	    cipher.init(Cipher.DECRYPT_MODE,creds.getKey(),new IvParameterSpec(creds.getIV()));
	}catch(Exception e){
	    System.out.println("AES.decrpyt init ERROR:"+e.getMessage());
	}
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
	    System.out.println("AES.decrypt doFinal() ERROR:"+e.getMessage());
	}
	try{
	    retval = new File(cipherText.getPath().concat(".plain"));
	    FileOutputStream fos = new FileOutputStream(retval);
	    fos.write(plain);
	    fos.flush();
	    fos.close();
	}catch(Exception e){
	    System.out.println("AES.decrypt File-Write ERROR:"+e.getMessage());
	}
	creds.setIV(cipher.getIV());
	return retval;
    }

    /**
     * Getter for Credential object within this AES-object
     * @return Credentials currently in this object
     * @see AES.Credential
     */
    public Credential getCreds(){
	return creds;
    }

    /**
     * Getter for cipher; not sure why you would need it....
     * @return Cipher object used by this class
     */
    public Cipher getCipher(){
	return cipher;
    }

    public static void main(String args[]) throws Exception{
	if(args.length!=1)
	    System.exit(-1);

	AES crypt = new AES();
	if(args[0].equals(new String(crypt.decrypt(crypt.encrypt(args[0])))))
	    System.out.println("Class: JavaAES is working!");

	byte[] plain=new byte[128];
	java.util.Random r=new java.util.Random();
	r.nextBytes(plain);
	byte[] cipher=crypt.encrypt(plain);
	byte[] newPlain=crypt.decrypt(cipher);
	byte[] iv=crypt.getCreds().getIV();
	byte[] key=crypt.getCreds().getKeyBytes();

	System.out.println("\r\nPlain:");
	for(byte b:plain)
	    System.out.print(b+",");

	System.out.println("\r\nCipher:");
	for(byte b:cipher)
	    System.out.print(b+",");

	System.out.println("\r\nNewPlain:");
	for(byte b:newPlain)
	    System.out.print(b+",");

	System.out.println("\r\nIV:");
	for(byte b:iv)
	    System.out.print(b+",");

	System.out.println("\r\nKey:");
	for(byte b:key)
	    System.out.print(b+",");

    }
}
