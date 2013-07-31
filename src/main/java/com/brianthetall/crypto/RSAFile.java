package com.brianthetall.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class RSAFile{

    private RSA rsa;
    private File file;

    public RSAFile(){
	rsa=new RSA();
	file=null;
    }

    public RSAFile(String fileName){

	rsa=new RSA();

	byte[] plainText;
	try{
	    java.io.File input = new java.io.File(fileName);
	    FileInputStream fis = new FileInputStream(input);
	    int fileSize = RSA.getFileSize(input);
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
	    System.exit(-1);
	}
	
	
	
    }

    public static void main(String args[]){
	if(args.length != 1){
	    System.err.println("RSAFile -e|-d <key-file> <file>");
	    System.exit(-1);
	}
	    
	new RSAFile(args[0]);
    }
    
}
