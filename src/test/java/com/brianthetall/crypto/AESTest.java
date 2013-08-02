package com.brianthetall.crypto;

import org.junit.Test;
import org.junit.Before;
import org.junit.After;
import org.junit.Assert;

/**
 * Unit test for AES class
 * AES.Credential isnt tested, it is assumed\
 * to work if AES is working.
 */

public class AESTest{

    private AES aes;

    @Before public void setup()throws Exception{
	aes=new AES();//runs a keygen and populates Credential
    }

    @Test public void constructorTest()throws Exception{

	java.util.Random r=new java.util.Random();

	byte[] plain=new byte[1024];
	r.nextBytes(plain);//get some data

	byte[] cipherText=aes.encrypt(plain);//now IV is populated

	AES aesUnderTest = new AES(aes.getCreds().getKey().getEncoded(),aes.getCreds().getIV());

	assert(aes.equals(aesUnderTest));

	byte[] plainA=aes.decrypt(cipherText);
	byte[] plainB=aesUnderTest.decrypt(cipherText);
	assert(plainA.length==plainB.length);
	for(int i=0;i<plainA.length;i++){
	    assert(plainA[i]==plainB[i]);
	}

    }

    @Test public void encryptByteArray(){

    }

    @Test public void encryptString(){

    }

    @Test public void encryptFile(){

    }

    @Test public void decryptByteArray(){

    }

    @Test public void decryptFile(){

    }

    @Test public void getCreds(){

    }

}
