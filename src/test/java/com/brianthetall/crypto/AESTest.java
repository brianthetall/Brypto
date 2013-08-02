package com.brianthetall.crypto;

import org.junit.Ignore;
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

    private byte[] plain=new byte[]{-74,-113,13,106,-58,111,-55,-16,9,-26,-34,-63,-98,-67,102,-116,-117,-20,60,-113,-86,125,31,-38,-59,127,25,56,-28,-5,90,-90,-113,24,-2,-71,28,1,50,127,45,-24,-91,61,-71,-113,-5,-17,24,121,88,-9,22,-116,-127,-73,-70,124,73,108,58,-89,-87,-113,-82,-101,-71,122,-64,-90,-60,-6,60,45,58,-96,41,35,30,-21,38,124,42,87,-15,-99,-4,11,13,2,53,91,21,115,-125,-28,-17,-105,74,-24,-11,53,42,-23,-119,81,-70,-15,-72,-113,14,20,-85,98,-104,85,-112,69,84,-102,-67,88,-45,-1,-97,-73,66,-27};

    private byte[] cipher=new byte[]{92,38,24,-69,-8,-69,-80,58,-83,19,117,-29,-42,36,-23,-56,-128,34,-59,-125,-43,-109,-16,-16,28,127,-118,-102,37,93,126,-7,-18,105,118,-44,-102,-81,-54,-96,68,85,111,-111,-94,72,-109,108,8,41,115,-19,10,70,33,-121,126,-86,-27,33,3,-14,-10,-117,-90,-128,-27,-109,-87,-18,107,-3,-58,-65,-56,16,85,-15,-41,4,81,32,109,-98,-18,11,-67,61,-128,-64,-87,-7,-117,36,-63,-107,41,-6,45,-54,18,-30,98,-10,14,76,-69,-89,41,29,78,12,99,-24,103,-44,-46,108,57,124,75,-105,52,-108,50,13,-6,-37,-127,32,-89,-9,66,24,-114,-89,-32,113,28,2,-74,79,58,-24,};

    private byte[] iv=new byte[]{-24,96,119,83,-126,72,92,-59,10,84,-4,121,15,84,87,123};

    private byte[] key=new byte[]{-87,57,6,115,105,93,63,-77,-7,-84,21,28,53,70,-93,104};

    private AES aes;

    /**
     * Setup a fresh AES object before each test
     */
    @Before public void setup()throws Exception{
	aes=new AES();//runs a keygen and populates Credential
    }

    /**
     * Null the AES reference after each test
     */
    @After public void unsetup(){
	aes=null;
    }

    /**
     * Verify that two AES-objects, created with differenct constructors, are equal
     */
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

    /**
     * Use the canned byte[]{plain,cipher} to verify
     */
    @Test public void encryptByteArray(){
	try{
	    aes.getCreds().setKey(key);
	    byte[] testCipherData=aes.encrypt(this.plain);
	    AES aesDecrypt=new AES(aes.getCreds().getKeyBytes(),aes.getCreds().getIV());
	    byte[] newPlain=aesDecrypt.decrypt(testCipherData);
	    assert(newPlain.length==plain.length);
	    for(int i=0;i<plain.length;i++)
		assert(plain[i]==newPlain[i]);
	    
	}catch(Exception e){
	    System.out.println(e.getMessage());
	    assert(false);//fail test
	}
    }

    /**
     * Use this canned byte[]{plain,cipher,iv,key} to verify
     */
    @Test public void decryptByteArray(){
	try{
	    aes.getCreds().setIV(iv);
	    aes.getCreds().setKey(key);
	    byte[] plainData=aes.decrypt(cipher);
	    assert(plainData.length==plain.length);
	    for(int i=0;i<plain.length;i++){
		assert(plain[i]==plainData[i]);
	    }
	}catch(Exception e){
	    System.err.println("AESTest.decryptByteArray:"+e.getMessage());
	    assert(false);//fail test
	}
    }

}
