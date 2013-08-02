package com.brianthetall.crypto;

import java.lang.Exception;
import java.util.Random;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.File;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.Before;
import org.junit.After;
import org.junit.Assert;

public class SecureFileTest{

    SecureFile sf;    
    private final String testFile="/home/ubuntu/photo.jpg";

    @Before public void setup(){
	sf=new SecureFile();
    }

    @After public void unsetup(){
	sf=null;
    }

    /**
     * Test ability to crypt a byte[]
     *
     */
    @Test public void encrypt(){
	byte[] random=new byte[512];
	new Random().nextBytes(random);//get some data
	byte[] cipherText=sf.encrypt(random);//encrypt
	byte[] isRandom=sf.decrypt(cipherText,null,null);

	for(int i=0;i<random.length;i++)
	    assert(random[i]==isRandom[i]);//confirm the bytes with random[]
    }

    /**
     * Verify both the encrypt and decrypt functions for java.io.File input.
     * use a Class defined test file (/proc/version) to verify.
     * The file used must be the same for duration of test.
     */
    @Test public void cryptFile(){
	File input = new File(testFile);
	File cipher=sf.encrypt(input);
	SecureFile test=new SecureFile();
	test.setCreds(sf.getCreds().getKeyBytes(),sf.getCreds().getIV());
	File plainTest=test.decrypt(cipher);

	assert(plainTest.length()==input.length());//check file lengths; fail-fast
	//check the file contents
	try{
	    DataInputStream control=new DataInputStream(new FileInputStream(input));
	    DataInputStream experiment=new DataInputStream(new FileInputStream(plainTest));
	    byte[] controlBytes=new byte[(int)input.length()];
	    byte[] experimentBytes=new byte[(int)input.length()];
	    control.readFully(controlBytes);
	    experiment.readFully(experimentBytes);
	    for(int i=0;i<controlBytes.length;i++)
		assert(controlBytes[i]==experimentBytes[i]);
	}catch(Exception e){
	    System.err.println(e.getMessage());
	}finally{
	    plainTest.delete();
	}
    } 
    
}
