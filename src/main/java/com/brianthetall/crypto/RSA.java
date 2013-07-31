package com.brianthetall.crypto;

import java.security.*;
import javax.crypto.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;

public class RSA{

    private KeyPair key;
    private Cipher cipher;

    public RSA(){
	//	System.out.println( "\nStart generating RSA key" );
	try{
	    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
	    keyGen.initialize(1024);//small key?
	    key = keyGen.generateKeyPair();
	}catch(NoSuchAlgorithmException e){
	    System.out.println("Nosuch Algorithm: RSA");
	}
	
	//	System.out.println( "Finish generating RSA key" );
	try{
	    // get an RSA cipher object and print the provider
	    cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	}catch(NoSuchAlgorithmException e){
	     System.out.println("Nosuch Algorithm: RSA");
	}catch(NoSuchPaddingException e){
	    System.out.println("No such padding exception: RSA.RSA");
	}
	
	System.out.println( "\nProvider i need to replace:" + cipher.getProvider().getInfo() );
    }

    public KeyPair getKeys(){
	return key;
    }

    public byte[] encrypt(byte[] plainText)throws Exception{

	// encrypt the plaintext using the public key
	cipher.init(Cipher.ENCRYPT_MODE, key.getPublic());
	byte[] cipherText = cipher.doFinal(plainText);

	//	System.out.println( "Encryption: " );
	//	System.out.println( new String(cipherText, "UTF8") );

	return cipherText;
    }

    public byte[] decrypt(byte[] cipherText)throws Exception{

	// decrypt the ciphertext using the private key
	cipher.init(Cipher.DECRYPT_MODE, key.getPrivate());
	byte[] newPlainText = cipher.doFinal(cipherText);

	//	System.out.println( "Decryption: " );
	//	System.out.println( new String(newPlainText, "UTF8") );

	return newPlainText;
    }

    protected static int getFileSize(java.io.File file){

	int retval=0;
	if(file == null)
	    return -1;

	try{
	    FileInputStream fis = new FileInputStream(file);
	    for(;fis.read()!=-1;retval++){}

	}catch(IOException e){
	    System.out.println("RSA.getFileSize() Errror");
	    return -2;
	}

	return retval;
    }

    public static void main(String args[])throws Exception{
	if (args.length !=2) {
	    System.out.println("Usage: java RSA --text <text>");
	    System.out.println("Usage: java RSA --file <file>");
	    System.exit(1);
	}
	RSA rsa = new RSA();

	byte[] plainText=null;

	if(args[0].equals("--text"))
	    plainText = args[1].getBytes("UTF8");

	else if(args[0].equals("--file")){

	    try{
		java.io.File input = new java.io.File(args[1]);
		FileInputStream fis = new FileInputStream(input);
		int fileSize = getFileSize(input);
		byte[] data = new byte[fileSize];
		System.out.println("FileSize="+fileSize);
		int offset=0,temp;
		while( -1 != (temp=fis.read(data,offset,fileSize)) ){//klklkl
		    offset += temp;
		    System.out.println("Offset="+offset);
		    if(offset==fileSize)
			break;
		}//read file into data[]
		plainText = data;

	    }catch(IOException e){
		System.out.println("Could not open file");
	    }

	}

	byte[] cipherText =rsa.encrypt(plainText);
	byte[] test = rsa.decrypt(cipherText);

	System.out.println("\r\nPlain:"+new String(plainText));
	System.out.println("\r\nCipher:"+new String(cipherText));
	System.out.println("\r\nPlain*:"+new String(test));
	
    }
}
