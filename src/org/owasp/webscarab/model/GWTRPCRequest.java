/*
* GWTRPCRequest.java
*
* Created on 16 December 2004, 05:08
*/

package org.owasp.webscarab.model;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import java.util.List;
import java.util.ArrayList;
import java.util.Iterator;

import java.io.UnsupportedEncodingException;

import javax.swing.JOptionPane;

//JLS - EDW
import java.util.Vector;
import java.util.Iterator;
import java.util.logging.Logger;

// JLS 2010-07-26 - GWT-RPC
import java.net.URL;
import java.net.URLConnection; 
import java.io.InputStream;
import java.io.FileOutputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedInputStream;
import java.nio.charset.Charset;

/**
*
* @author  rogan
*/
public class GWTRPCRequest {
	
	private byte[] _bytes;
	private Vector<String> contentVectorized = new Vector<String> ();
	// JLS EDW
	private static Logger _logger = Logger.getLogger("org.owasp.webscarab.ui.swing.editors.GWTRPCRequest");
	
	/** Creates a new instance of GWTRPCRequest */
	public GWTRPCRequest(String contentType, byte[] content) {
		if (contentType != null && content != null) {
			setBytes(contentType, content);
		}
        }
        
        public int size() {
        	return contentVectorized.size();
        }
        
        public byte[] getBytes() {
        	return (JavaObjectToGWTRPC(contentVectorized));
        }
        
        public void setBytes (String contentType,  byte[] content) {
		if (contentType != null && contentType.trim().startsWith("text/x-gwt-rpc")) {
			contentVectorized = GWTRPCToJavaObject(content);
			_bytes = content;
		}
	}
        	
        public Vector<String> getVector() {
        	return (contentVectorized);
        }

        public void setVector (Vector<String> newVector) {
        	if (newVector != null) {
        		contentVectorized = newVector;
        		JavaObjectToGWTRPC(contentVectorized);
        	}
        }

        public static Vector<String> GWTRPCToJavaObject(byte [] bytes) {
		Vector<String> currentArray = new Vector<String> ();
		if (bytes == null) {
			System.out.println ("Null parameter found, returning");
			return (null);
		} else {
			int indexStart = 0;
			int indexEnd = 0;
			/*
			Marquer le début du tableau
			Parcourir le tableau tant que le caractère lu est différent de "EF" et que l'on est pas à la fin.
			Lorsque le caractère "EF" est trouvé, marqué la fin de l'index sur la case précédente
			Si la case suivante est "BF" et la case +2 est "BF" alors on a un tag de fin de champ
			Ajouter un string avec le tableau indexStart->indexEnd
			Passer indexStart à indexEnd+4 (indexFin=>EF=>BF=>BF=>Nouveau champ)
			Recommencer jusqu'à ce que la fin du tableau soit atteinte
			*/
			String stringToAdd = null;
			while (indexEnd < bytes.length) {
				while (indexEnd < bytes.length && bytes[indexEnd] != -17) {
					//System.out.println("Byte["+indexEnd+"]: "+bytes[indexEnd]);
					indexEnd++;
				}
				if (indexEnd+2 < bytes.length) {
					if (bytes[indexEnd+1] == -65 && bytes[indexEnd+2] == -65) {
						_logger.finest("Found new END-tag.");
						stringToAdd = new String (bytes, indexStart, indexEnd-indexStart, Charset.defaultCharset()) ;
						currentArray.add(stringToAdd);
						_logger.finest("Adding string: "+stringToAdd);
						indexEnd = indexEnd + 3;
						indexStart = indexEnd;
					} else {
						_logger.finest("Weird END-tag found at index: "+indexEnd);
						_logger.finest("Jumping three times");
						indexEnd = indexEnd + 3;
						indexStart = indexEnd;
					}
				} else {
					_logger.finest("Found new END-tag but too close from the end.");
					_logger.finest("ignoring it END-tag.");
					stringToAdd = new String (bytes, indexStart, indexEnd-indexStart, Charset.defaultCharset()) ;
					currentArray.add(stringToAdd);
					_logger.finest("Adding string: "+stringToAdd);
					indexEnd = indexEnd + 3;
					indexStart = indexEnd;
				}
			}
			return (currentArray);
		}
	}
	
	public static byte [] JavaObjectToGWTRPC(Vector currentArray) {
		byte[] _data = new byte[0];
		try {
			// Vector permits to use several java streams
			Vector v = currentArray ;
			String o = null;
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			
			// JLS - EDW
			Iterator itr = v.iterator();
			while (itr.hasNext()) {
				o = (String) itr.next();
				baos.write (o.getBytes(),0,o.length());
				byte [] tag = {-17, -65, -65};
				baos.write (tag,0,3);
				baos.flush();
			}
			_data = baos.toByteArray();
		} catch (IOException ioe) {
			System.err.println("Error serialising the object : " + ioe);
			return null;
		}
		return _data;
	}
	
	
	
	public static void main(String[] args) {
		Request request = new Request();
		try {
			// JLS - 2010-07-20 modification of the test
			//java.io.FileInputStream fis = new java.io.FileInputStream("/home/rogan/csob/3/conversations/4-request");
			java.io.FileInputStream fis = new java.io.FileInputStream("/tmp/test-POST-multipart");
			request.read(fis);
			GWTRPCRequest mpc = new GWTRPCRequest(request.getHeader("Content-Type"), request.getContent());
			System.out.println("Got " + mpc.size());
			//Message message = mpc.get(0);
			// JLS - 2010-07-20 Added a loop
			//System.out.println("First part is " + message.getHeader("Content-Disposition") + " = '" + new String(message.getContent()) + "'");
			/* for  (int i = 0; i <mpc.size(); i++) {
				message = mpc.get (i);
				System.out.println("Part "+i+" is " + mpc.getPartName(i) + " = '" + new String(message.getContent()) + "'");
			} */
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
}
