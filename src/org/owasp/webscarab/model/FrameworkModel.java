/***********************************************************************
 *
 * $CVSHeader$
 *
 * This file is part of WebScarab, an Open Web Application Security
 * Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2004 Rogan Dawes
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * Getting Source
 * ==============
 *
 * Source for this application is maintained at Sourceforge.net, a
 * repository for free software projects.
 *
 * For details, please see http://www.sourceforge.net/projects/owasp
 *
 */

/*
 * SiteModel.java
 *
 * Created on July 13, 2004, 3:58 PM
 */

package org.owasp.webscarab.model;

import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.logging.Logger;
import java.util.logging.Level;

import javax.swing.event.EventListenerList;

import org.owasp.webscarab.util.MRUCache;

import java.io.File;

/**
 * Provides a model of the conversations that have been seen
 * @author rogan
 */
public class FrameworkModel {
    
    //private ReentrantReaderPreferenceReadWriteLock _rwl = new ReentrantReaderPreferenceReadWriteLock();
	private ReentrantReadWriteLock _rwl = new ReentrantReadWriteLock();
    
    private static final Cookie[] NO_COOKIES = new Cookie[0];
    
    private EventListenerList _listenerList = new EventListenerList();
    
    // keeps a fairly small cache of recently used HttpUrl objects
    private Map<ConversationID, HttpUrl> _urlCache = new MRUCache<ConversationID, HttpUrl>(200);
    
    private SiteModelStore _store = null;
    
    private FrameworkUrlModel _urlModel;
    private FrameworkConversationModel _conversationModel;
    
    private boolean _modified = false;
    private Boolean DEBUG_WRITE_LOCK = Boolean.FALSE;
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    /**
     * Creates a new ConversationModel
     */
    public FrameworkModel() {
        _logger.setLevel(Level.INFO);
        _conversationModel = new FrameworkConversationModel(this);
        _urlModel = new FrameworkUrlModel();
    }
    
    public void setSession(String type, Object store, String session) throws StoreException {        
    	if (type.equals("FileSystem") && store instanceof File) {
    		// Get the lock to modify the session
    		try {
    			writeLock();
    		} catch (InterruptedException ie) {
    			_logger.severe("Interrupted! " + ie);
    			throw new StoreException("Error while acquiring lock: " + ie.getMessage());
    		}
    		// Create the new session
    		try {
    			_store = new FileSystemStore((File) store);
    			writeUnlock();
    		} catch (Exception e) {
    			writeUnlock();
    			throw new StoreException("Error initialising session : " + e.getMessage());
    		}
    		// Signal the modifications
    		_urlModel.fireUrlsChanged();
    		_conversationModel.fireConversationsChanged();
    		fireCookiesChanged();
    	} else {
    		throw new StoreException("Unknown store type " + type + " and store " + store);
    	}
    }
    
    protected void writeLock() throws InterruptedException {
    	if (DEBUG_WRITE_LOCK) {
    		System.err.println("\n");
    		_logger.severe("BEGIN ############################################");
    		_logger.severe("_rwl.writeLock().lockInterruptibly() TRY");
    		_logger.severe("Writelock is locked: " + _rwl.isWriteLocked());
    		_logger.severe("Writelock is from:");
    		Thread.dumpStack();
    	}
		_rwl.writeLock().lockInterruptibly();
    	if (DEBUG_WRITE_LOCK) {
    		_logger.severe("_rwl.writeLock().lockInterruptibly() DONE");
    		_logger.severe("END ---------------------------------------------");
    		System.err.println("\n\n");
    	}
    }

    protected void writeUnlock() {
    	if (DEBUG_WRITE_LOCK) {
    		_logger.severe("_rwl.writeLock().unlock()");
    	}
		_rwl.writeLock().unlock();
    }

    protected void readLock() throws InterruptedException {
    	if (DEBUG_WRITE_LOCK) {
    		System.err.println("\n");
    		_logger.severe("READ BEGIN //////////////////////////////////////////////");
    		_logger.severe("_rwl.readLock().lockInterruptibly() TRY");
    		_logger.severe("Lock has currently " + _rwl.getReadLockCount() + " read locks.");
    		Thread.dumpStack();
    	}
		_rwl.readLock().lockInterruptibly();
    	if (DEBUG_WRITE_LOCK) {
    		_logger.severe("_rwl.readLock().lockInterruptibly() DONE");
    		_logger.severe("Lock has currently " + _rwl.getReadLockCount() + " read locks.");
    		_logger.severe("READ END ................................................");
    		System.err.println("\n\n");
    	}
    }

    protected void readUnlock() {
    	if (DEBUG_WRITE_LOCK) {
    		_logger.severe("_rwl.readLock().unlock()");
    	}
    	_rwl.readLock().unlock();
    	if (DEBUG_WRITE_LOCK) {
    		_logger.severe("Lock has NOW " + _rwl.getReadLockCount() + " read locks.");
    	}
    }

    public UrlModel getUrlModel() {
        return _urlModel;
    }
    
    public ConversationModel getConversationModel() {
        return _conversationModel;
    }
    
    /**
     * instructs the SiteModel to flush any unwritten data in the underlying store to
     * disk, prior to exit.
     * @throws StoreException if there is any problem writing to the store
     */
    public void flush() throws StoreException {
        if (_modified) {
            try {
                readLock();
                    _store.flush();
                    _modified = false;
                    readUnlock();
            } catch (InterruptedException ie) {
                _logger.severe("Interrupted! " + ie);
            }
        }
    }
    
    /**
     * indicates whether there have been modifications to the site model
     *@return true if the model has been modified since it was last flushed, false otherwise
     */
    public boolean isModified() {
        return _modified;
    }
    
    /**
     * reserve a conversation ID for later use. This is mostly used by the Proxy plugin
     * to allow it to add conversations in the order that they are seen, not in the
     * order that they are completed.
     * @return a new ConversationID
     */
    public ConversationID reserveConversationID() {
        return new ConversationID();
    }
    
    /**
     * adds a request and a response to the model, also specifying which plugin caused
     * it.
     * @param id the previously reserved ConversationID that identifies this conversation
     * @param request the request
     * @param response the response from the server
     * @param origin the plugin that created this conversation
     */
    public void addConversation(ConversationID id, Date when, Request request, Response response, String origin) {
    	HttpUrl url = request.getURL();
    	addUrl(url); // fires appropriate events
    	Boolean locked = Boolean.FALSE;
    	// Get the lock
    	try {
    		writeLock();
    		locked = Boolean.TRUE;
    	} catch (InterruptedException ie) {
    		_logger.severe("Interrupted! " + ie);
    	} 
    	if (locked) {
    		int index = _store.addConversation(id, when, request, response);
    		_store.setConversationProperty(id, "METHOD", request.getMethod());
    		_store.setConversationProperty(id, "URL", request.getURL().toString());
    		_store.setConversationProperty(id, "STATUS", response.getStatusLine());
    		_store.setConversationProperty(id, "WHEN", Long.toString(when.getTime()));
    		_store.setConversationProperty(id, "ORIGIN", origin);
    		byte[] content=response.getContent();
    		if (content != null && content.length > 0) {
    			_store.setConversationProperty(id, "RESPONSE_SIZE", Integer.toString(content.length));
    		}
    		writeUnlock();
    		_conversationModel.fireConversationAdded(id, index); // FIXME
    		addUrlProperty(url, "METHODS", request.getMethod());
    		addUrlProperty(url, "STATUS", response.getStatusLine());
    		_modified = true;
    	}
    }
    
    public String getConversationOrigin(ConversationID id) {
        return getConversationProperty(id, "ORIGIN");
    }
    
    public Date getConversationDate(ConversationID id) {
    	Boolean readLocked = Boolean.FALSE;
    	Date returnValue = null;
        /*
    	try {
            readLock();
            readLocked = Boolean.TRUE;
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
        }
        */
          //  if(readLocked) {
                String when = getConversationProperty(id, "WHEN");
          //      readUnlock();
                if (null != when) {
                try {
                    long time = Long.parseLong(when);
                    returnValue = new Date(time);
                } catch (NumberFormatException nfe) {
                    _logger.severe("NumberFormatException parsing date for Conversation " + id + ": " + nfe);
                }
                }
           // }
            return returnValue;
    }
    
    /**
     * returns the url of the conversation in question
     * @param conversation the conversation
     * @return the url
     */
    
    public HttpUrl getRequestUrl(ConversationID conversation) {
    	HttpUrl returnValue = null;
        try {
            readLock();
                // this allows us to reuse HttpUrl objects
                if (_urlCache.containsKey(conversation)) {
                	returnValue = (HttpUrl) _urlCache.get(conversation);
                	readUnlock();
                } else {
                	// URL is not in cache
                	readUnlock();
                String url = getConversationProperty(conversation, "URL");
                HttpUrl httpUrl = null;
                try {
                    httpUrl = new HttpUrl(url);
                } catch (MalformedURLException mue) {
                	_logger.severe("Malformed URL for Conversation " + conversation + ": " + mue);
                }
                if(null != httpUrl) {
                	Boolean writeLocked = Boolean.FALSE;
                	try {
                		writeLock();
                		writeLocked = Boolean.TRUE;
                	} catch (InterruptedException ie) {
                		_logger.severe("Interrupted! " + ie);
                	}
                	if (writeLocked) {
                		_urlCache.put(conversation, httpUrl);
                		returnValue = httpUrl;
                		writeUnlock();
                	}
                }
                }
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
        }
        return returnValue;
    }
    
    /**
     * sets the specified property of the conversation
     * @param conversation the conversation ID
     * @param property the name of the property to change
     * @param value the value to use
     */
    public void setConversationProperty(ConversationID conversation, String property, String value) {
    	Boolean locked = Boolean.FALSE;
    	// Get the lock
    	try {
            writeLock();
            locked = Boolean.TRUE;
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
        }
    	if (locked) {
            _store.setConversationProperty(conversation, property, value);
            writeUnlock();
            _conversationModel.fireConversationChanged(conversation, 0); // FIXME
            fireConversationPropertyChanged(conversation, property);
        _modified = true;
    	}
    }
    
    /**
     * adds the value to a list of existing values for the specified property and conversation
     * @param conversation the conversation
     * @param property the name of the property
     * @param value the value to add
     */
    public boolean addConversationProperty(ConversationID conversation, String property, String value) {
        boolean change = false;
        Boolean locked = Boolean.FALSE;
    	// Get the lock
        try {
            writeLock();
            locked = Boolean.TRUE;
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
        }
    	if (locked) {
            change = _store.addConversationProperty(conversation, property, value);
            writeUnlock();
            if (change) {
                _conversationModel.fireConversationChanged(conversation, 0); // FIXME
                fireConversationPropertyChanged(conversation, property);
            }
        _modified = _modified || change;
    	}
        return change;
    }
    
    /**
     * returns a String containing the value that has been identified for a particular conversation property
     * @param conversation the conversation id
     * @param property the name of the property
     * @return the property value, or null if none has been set
     */
    public String getConversationProperty(ConversationID conversation, String property) {
        String[] values = getConversationProperties(conversation, property);
        if (values == null || values.length == 0) return null;
        if (values.length == 1) return values[0];
        StringBuffer value = new StringBuffer(values[0]);
        for (int i=1; i<values.length; i++) value.append(", ").append(values[i]);
        return value.toString();
    }
    
    public String getRequestMethod(ConversationID id) {
        return getConversationProperty(id, "METHOD");
    }
    
    public String getResponseStatus(ConversationID id) {
        return getConversationProperty(id, "STATUS");
    }
    
    /**
     * returns a String array containing the values that has been set for a particular conversation property
     * @param conversation the conversation id
     * @param property the name of the property
     * @return an array of strings representing the property values, possibly zero length
     */
    public String[] getConversationProperties(ConversationID conversation, String property) {
    	// TODO: not better to use String[0] ?
    	String[] properties = null;
    	if (null != _store) {
    		try {
    			readLock();
    			properties = _store.getConversationProperties(conversation, property);
    			readUnlock();
    		} catch (InterruptedException ie) {
    			_logger.severe("Interrupted! " + ie);
    		}
    	}
    	return properties;
    }
    
    private void addUrl(HttpUrl url) {
    	Boolean readLocked = Boolean.FALSE;
    	Boolean writeLocked = Boolean.FALSE;
    	// Get the read lock to look for the URL
        try {
            readLock();
            readLocked = Boolean.TRUE;
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
        }

            //try {
        // If the URL is not known
                if (readLocked) {
                	Boolean isKnown = _store.isKnownUrl(url);
                	readUnlock();
                    readLocked = Boolean.FALSE;
                	if (!isKnown) {
                    HttpUrl[] path = url.getUrlHierarchy();
                    // We prepared the URL to add and go for it
                    for (int i=0; i<path.length; i++) {
                    	// Get the read lock again to be sure it's not present
                    	try {
                            readLock();
                            readLocked = Boolean.TRUE;
                        } catch (InterruptedException ie) {
                            _logger.severe("Interrupted! " + ie);
                        }
                    	// If it's not present, we add it
                        if (readLocked) {
                        	isKnown = _store.isKnownUrl(path[i]);
                        	// Release the read lock
                    		readUnlock();
                    		readLocked = Boolean.FALSE;
                    		if (!isKnown) {
                        	// Get the Write lock
                        	try {
                        		writeLock();
                        		writeLocked = Boolean.TRUE;
                        	} catch (InterruptedException ie) {
                        		_logger.severe("Interrupted! " + ie);
                        	}
                        	// We managed to get the write lock so we add it to the store and release it.
                        	if (writeLocked) {
                                _store.addUrl(path[i]);
                                writeUnlock();
                                writeLocked = Boolean.FALSE;
                                _modified = true;
                                _urlModel.fireUrlAdded(path[i], 0);
                        	} else {
                        		_logger.severe("Unable to write lock the store. Should not happen!");
                            }
                    		}
                        }
                    }
                	}
                }
    }
    
    /**
     * sets the specified property of the url
     * @param url the url
     * @param property the name of the property to change
     * @param value the value to use
     */
    public void setUrlProperty(HttpUrl url, String property, String value) {
        addUrl(url);
    	Boolean writeLocked = Boolean.FALSE;
        try {
            writeLock();
            writeLocked = Boolean.TRUE;
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
        }
            if (writeLocked) {
            _store.setUrlProperty(url, property, value);
            //readLock(); // downgrade write to read
            writeUnlock();
            _urlModel.fireUrlChanged(url, 0); // FIXME
            fireUrlPropertyChanged(url, property);
            //readUnlock();
        _modified = true;
            }
    }
    
    /**
     * adds the value to a list of existing values for the specified property and Url
     * @param url the url
     * @param property the name of the property
     * @param value the value to add
     */
    public boolean addUrlProperty(HttpUrl url, String property, String value) {
        boolean change = false;
        addUrl(url);
    	Boolean writeLocked = Boolean.FALSE;
        try {
            writeLock();
            writeLocked = Boolean.TRUE;
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
        }
        if (writeLocked) {
            change = _store.addUrlProperty(url, property, value);
            //readLock();
            writeUnlock();
            if (change) {
                _urlModel.fireUrlChanged(url, 0);
                fireUrlPropertyChanged(url, property);
            }
            //readUnlock();
        _modified = _modified || change;
        }
        return change;
    }
    
    /**
     * returns a String array containing the values that has been set for a particular url property
     * @param url the url
     * @param property the name of the property
     * @return an array of strings representing the property values, possibly zero length
     */
    public String[] getUrlProperties(HttpUrl url, String property) {
    	String[] urlProperties = null;
    	if (null != _store) {
    		try {
    			readLock();
    			urlProperties = _store.getUrlProperties(url, property);
    			readUnlock();
    		} catch (InterruptedException ie) {
    			_logger.severe("Interrupted! " + ie);
    		}
    	}
    	return urlProperties;
    }
    
    /**
     * returns a String containing the value that has been identified for a particular url property
     * @param url the url
     * @param property the name of the property
     * @return the property value, or null if none has been set
     */
    public String getUrlProperty(HttpUrl url, String property) {
        String[] values = getUrlProperties(url, property);
        if (values == null || values.length == 0) return null;
        if (values.length == 1) return values[0];
        StringBuffer value = new StringBuffer(30);
        value.append(values[0]);
        for(int i=1; i< values.length; i++) value.append(", ").append(values[i]);
        return value.toString();
    }
    
    /**
     * returns the request corresponding to the conversation ID
     * @param conversation the conversation ID
     * @return the request
     */
    public Request getRequest(ConversationID conversation) {
    	Request request = null;
    	if (null != _store) {
    		try {
    			readLock();
    			request = _store.getRequest(conversation);
    			readUnlock();
    		} catch (InterruptedException ie) {
    			_logger.severe("Interrupted! " + ie);
    		}
    	}
    	return request;
    }
    
    /**
     * returns the response corresponding to the conversation ID
     * @param conversation the conversation ID
     * @return the response
     */
    public Response getResponse(ConversationID conversation) {
    	Response response = null;
    	if (null != _store) {
    		try {
    			readLock();
    			response = _store.getResponse(conversation);
    			readUnlock();
    		} catch (InterruptedException ie) {
    			_logger.severe("Interrupted! " + ie);
    		}
    	}
    	return response;
    }
    
    /**
     * adds a listener to the model
     * @param listener the listener to add
     */
    public void addModelListener(FrameworkListener listener) {
        synchronized(_listenerList) {
            _listenerList.add(FrameworkListener.class, listener);
        }
    }
    
    /**
     * removes a listener from the model
     * @param listener the listener to remove
     */
    public void removeModelListener(FrameworkListener listener) {
        synchronized(_listenerList) {
            _listenerList.remove(FrameworkListener.class, listener);
        }
    }
    
    /**
     * returns the number of uniquely named cookies that have been added to the model.
     * This does not consider changes in value of cookies.
     * @return the number of cookies
     */
    public int getCookieCount() {
    	int cookiesCount = 0;
    	if (null != _store) {
    		try {
    			readLock();
    			cookiesCount = _store.getCookieCount();
    			readUnlock();
    		} catch (InterruptedException ie) {
    			_logger.severe("Interrupted! " + ie);
    		}
    	}
    	return cookiesCount;
    }
    
    /**
     * returns the number of unique values that have been observed for the specified cookie
     * @param key a key identifying the cookie
     * @return the number of values in the model
     */
    public int getCookieCount(String key) {
    	int cookiesCount = 0;
    	if (null != _store) {
    		try {
    			readLock();
    			cookiesCount = _store.getCookieCount(key);
    			readUnlock();
    		} catch (InterruptedException ie) {
    			_logger.severe("Interrupted! " + ie);
    		}
    	}
    	return cookiesCount;
    }
    
    /**
     * returns a key representing the cookie name at the position specified
     * @return a key which can be used to get values for this cookie
     * @param index which cookie in the list
     */
    public String getCookieAt(int index) {
    	String cookie = null;
    	if (null != _store) {
    		try {
    			readLock();
    			cookie = _store.getCookieAt(index);
    			readUnlock();
    		} catch (InterruptedException ie) {
    			_logger.severe("Interrupted! " + ie);
    		}
    	}
    	return cookie;
    }
    
    /**
     * returns the actual Cookie corresponding to the key and position specified
     * @param key the cookie identifier
     * @param index the position in the list
     * @return the cookie
     */
    public Cookie getCookieAt(String key, int index) {
    	Cookie cookie = null;
    	if (null != _store) {
    		try {
    			readLock();
    			cookie = _store.getCookieAt(key, index);
    			readUnlock();
    		} catch (InterruptedException ie) {
    			_logger.severe("Interrupted! " + ie);
    		}
    	}
    	return cookie;
    }
    
    /**
     * returns the position of the cookie in its list.
     * (The key is extracted from the cookie itself)
     * @param cookie the cookie
     * @return the position in the list
     */
    public int getIndexOfCookie(Cookie cookie) {
    	int indexOfCookie = 0;
    	if(null != _store) {
    		try {
    			readLock();
    			indexOfCookie = _store.getIndexOfCookie(cookie);
    			readUnlock();
    		} catch (InterruptedException ie) {
    			_logger.severe("Interrupted! " + ie);
    		}
    	}
    	return indexOfCookie;
    }
    
    /**
     * returns the position of the cookie in its list.
     * (The key is extracted from the cookie itself)
     * @param cookie the cookie
     * @return the position in the list
     */
    public int getIndexOfCookie(String key, Cookie cookie) {
    	int indexOfCookie = 0;
    	if(null != _store) {
    		try {
    			readLock();
    			indexOfCookie = _store.getIndexOfCookie(key, cookie);
    			readUnlock();
    		} catch (InterruptedException ie) {
    			_logger.severe("Interrupted! " + ie);
    		}
    	}
    	return indexOfCookie;
    }
    
    public Cookie getCurrentCookie(String key) {
    	Cookie currentCookie = null;
    	if (null != _store) {
    		try {
    			readLock();
    			int count = _store.getCookieCount(key);
    			currentCookie = _store.getCookieAt(key, count-1);
    			readUnlock();
    		} catch (InterruptedException ie) {
    			_logger.severe("Interrupted! " + ie);
    		}
    	}
    	return currentCookie;
    }
    
    /**
     * adds a cookie to the model
     * @param cookie the cookie to add
     */
    public void addCookie(Cookie cookie) {
    	Boolean writeLocked = Boolean.FALSE;
        try {
            writeLock();
            writeLocked = Boolean.TRUE;
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
        }
        if(writeLocked) {
            boolean added = _store.addCookie(cookie);
            writeUnlock();
            
            if (added) {
                _modified = true;
                //readLock();
                //writeUnlock();
                fireCookieAdded(cookie);
                //readUnlock();
            }
        }
    }
    
    /**
     * removes a cookie from the model
     * @param cookie the cookie to remove
     */
    public void removeCookie(Cookie cookie) {
    	Boolean writeLocked = Boolean.FALSE;
        try {
            writeLock();
            writeLocked = Boolean.TRUE;
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
        }
        if(writeLocked) {
            boolean deleted = _store.removeCookie(cookie);
            writeUnlock();
            if (deleted) {
                _modified = true;
                //readLock();
                //writeUnlock();
                fireCookieRemoved(cookie);
                //readUnlock();
            }
        }
    }
    
    /**
     * returns an array of cookies that would be applicable to a request sent to the url.
     * @param url the url
     * @return an array of cookies, or a zero length array if there are none applicable.
     */
    public Cookie[] getCookiesForUrl(HttpUrl url) {
    	Cookie[] cookiesReturned = NO_COOKIES;
    	if (null != _store) {
    		try {
    			readLock();
    			List<Cookie> cookies = new ArrayList<Cookie>();

    			String host = url.getHost();
    			String path = url.getPath();

    			int size = getCookieCount();
    			for (int i=0; i<size; i++) {
    				String key = getCookieAt(i);
    				Cookie cookie = getCurrentCookie(key);
    				String domain = cookie.getDomain();
    				if (host.equals(domain) || (domain.startsWith(".") && host.endsWith(domain))) {
    					if (path.startsWith(cookie.getPath())) {
    						cookies.add(cookie);
    					}
    				}
    			}
    			cookiesReturned = cookies.toArray(NO_COOKIES);
    			readUnlock();
    		} catch (InterruptedException ie) {
    			_logger.severe("Interrupted! " + ie);
    		}
    	}
    	return cookiesReturned;
    }
    
    /**
     * notifies listeners that a completely new cookie was added
     * @param cookie the cookie
     */
    protected void fireCookieAdded(Cookie cookie) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        FrameworkEvent evt = new FrameworkEvent(this, cookie);
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==FrameworkListener.class) {
                try {
                    ((FrameworkListener)listeners[i+1]).cookieAdded(evt);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                }
            }
        }
    }
    
    /**
     * notifies listeners that all values for cookie have been removed.
     * @param cookie the last cookie that was removed
     */
    protected void fireCookieRemoved(Cookie cookie) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        FrameworkEvent evt = new FrameworkEvent(this, cookie);
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==FrameworkListener.class) {
                try {
                    ((FrameworkListener)listeners[i+1]).cookieRemoved(evt);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                }
            }
        }
    }
    
    /**
     * notifies listeners that all cookies in the model have changed
     */
    protected void fireCookiesChanged() {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==FrameworkListener.class) {
                try {
                    ((FrameworkListener)listeners[i+1]).cookiesChanged();
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                }
            }
        }
    }
    
    /**
     * notifies listeners that a conversation property changed
     * @param cookie the cookie
     */
    protected void fireConversationPropertyChanged(ConversationID id, String property) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        FrameworkEvent evt = new FrameworkEvent(this, id, property);
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==FrameworkListener.class) {
                try {
                    ((FrameworkListener)listeners[i+1]).conversationPropertyChanged(evt);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                }
            }
        }
    }
    
    /**
     * notifies listeners that an URL property changed
     * @param cookie the cookie
     */
    protected void fireUrlPropertyChanged(HttpUrl url, String property) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        FrameworkEvent evt = new FrameworkEvent(this, url, property);
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==FrameworkListener.class) {
                try {
                    ((FrameworkListener)listeners[i+1]).urlPropertyChanged(evt);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                }
            }
        }
    }
    
    private class FrameworkUrlModel extends AbstractUrlModel {
         public int getChildCount(HttpUrl parent) {
        	int childCount = 0;
        	if (null != _store) {
        		try {
        			readLock();
        			childCount = _store.getChildCount(parent);
        			readUnlock();
        		} catch (InterruptedException ie) {
        			_logger.severe("Interrupted! " + ie);
        		}
        	}
        	return childCount;
        }
        
        public int getIndexOf(HttpUrl url) {
        	int index = -1;
        	if (null != _store) {
        		try {
        			readLock();
        			index = _store.getIndexOf(url);
        			readUnlock();
        		} catch (InterruptedException ie) {
        			_logger.severe("Interrupted! " + ie);
        		}
        	}
        	return index;
        }

        public HttpUrl getChildAt(HttpUrl parent, int index) {
        	HttpUrl url = null;
        	if (null != _store) {
        		try {
        			readLock();
        			url = _store.getChildAt(parent, index);
        			readUnlock();
        		} catch (InterruptedException ie) {
        			_logger.severe("Interrupted! " + ie);
        		}
        	}
        	return url;
        }
        
    }
    
    private class FrameworkConversationModel extends AbstractConversationModel {
        
        public FrameworkConversationModel(FrameworkModel model) {
            super(model);
        }
        /*
        public Sync readLock() {
            return _rwl.readLock();
        }
        */
        public ConversationID getConversationAt(int index) {
        	ConversationID cid = null;
        	if (null != _store) {
        		try {
        			readLock();
        			cid = _store.getConversationAt(null, index);
        			readUnlock();
        		} catch (InterruptedException ie) {
        			_logger.severe("Interrupted! " + ie);
        		}
        	}
        	return cid;
        }
        
        public int getConversationCount() {
        	int numberOfConversations = 0;
        	if (null != _store) {
        		try {
        			readLock();
        			numberOfConversations = _store.getConversationCount(null);
        			readUnlock();

        		} catch (InterruptedException ie) {
        			_logger.severe("Interrupted! " + ie);
        		}
        	}
        	return numberOfConversations;
        }
        
        public int getIndexOfConversation(ConversationID id) {
        	// TODO: -1 should not be better ?
        	int indexOfConversation = 0;
        	if (null != _store) {
        		try {
        			readLock();
        			indexOfConversation = _store.getIndexOfConversation(null, id);
        			readUnlock();
        		} catch (InterruptedException ie) {
        			_logger.severe("Interrupted! " + ie);
        		}
        	}
        	return indexOfConversation;
        }
        
    }
    
}
