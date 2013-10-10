/*
 * UrlModel.java
 *
 * Created on 13 April 2005, 03:58
 */

package org.owasp.webscarab.model;

/**
 *
 * @author  rogan
 */
public interface UrlModel {

    int getChildCount(HttpUrl parent);
    
    HttpUrl getChildAt(HttpUrl parent, int index);
    
    int getIndexOf(HttpUrl url);
        
    void addUrlListener(UrlListener listener);
    
    void removeUrlListener(UrlListener listener);
    
}
