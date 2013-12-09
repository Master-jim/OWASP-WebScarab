/*
 * FilteredConversationModel.java
 *
 * Created on 13 April 2005, 06:33
 */

package org.owasp.webscarab.model;

import EDU.oswego.cs.dl.util.concurrent.Sync;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.owasp.webscarab.util.ReentrantReaderPreferenceReadWriteLock;

/**
 *
 * @author  rogan
 */
public abstract class FilteredConversationModel extends AbstractConversationModel {
    
    private ConversationModel _model;
    
    private ReentrantReaderPreferenceReadWriteLock _rwl = new ReentrantReaderPreferenceReadWriteLock();
    
    // contains conversations that should be visible
    private List<ConversationID> _conversations = new ArrayList<ConversationID>();
    
    /** Creates a new instance of FilteredConversationModel */
    public FilteredConversationModel(FrameworkModel model, ConversationModel cmodel) {
        super(model);
        _model = cmodel;
        _model.addConversationListener(new Listener());
        updateConversations();
    }
    
    protected void updateConversations() {
    	Boolean writeLocked = Boolean.FALSE;
        try {
            _rwl.writeLock().acquire();
            writeLocked = Boolean.TRUE;
        } catch (InterruptedException ie) {
            // _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
        }
        if (writeLocked) {
            _conversations.clear();
            int count = _model.getConversationCount();
            for (int i=0 ; i<count; i++) {
                ConversationID id = _model.getConversationAt(i);
                if (!shouldFilter(id)) {
                    _conversations.add(id);
                }
            }
            _rwl.writeLock().release();
            fireConversationsChanged();
        }
    }
    
    public abstract boolean shouldFilter(ConversationID id);
    
    protected boolean isFiltered(ConversationID id) {
    	Boolean readLocked = Boolean.FALSE;
    	boolean valueReturned = false;
        try {
            _rwl.readLock().acquire();
            readLocked = Boolean.TRUE;
        } catch (InterruptedException ie) {
            // _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
        }
        if (readLocked) {
        	valueReturned = (_conversations.indexOf(id) == -1);
            _rwl.readLock().release();
        }
        return valueReturned;
    }
    
    public ConversationID getConversationAt(int index) {
    	Boolean readLocked = Boolean.FALSE;
    	ConversationID valueReturned = null;
        try {
            _rwl.readLock().acquire();
            readLocked = Boolean.TRUE;
        } catch (InterruptedException ie) {
            // _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
        }
        if (readLocked) {
        	valueReturned = _conversations.get(index);
            _rwl.readLock().release();
        }
        return valueReturned;
    }
    
    public int getConversationCount() {
    	Boolean readLocked = Boolean.FALSE;
    	int valueReturned = 0;
        try {
            _rwl.readLock().acquire();
            readLocked = Boolean.TRUE;
        } catch (InterruptedException ie) {
            // _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
        }
        if (readLocked) {
        	valueReturned = _conversations.size();
            _rwl.readLock().release();
        }
        return valueReturned;
    }
    
    public int getIndexOfConversation(ConversationID id) {
    	Boolean readLocked = Boolean.FALSE;
    	int valueReturned = -1;
        try {
            _rwl.readLock().acquire();
            readLocked = Boolean.TRUE;
        } catch (InterruptedException ie) {
            // _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
        }
        if (readLocked) {
        	valueReturned = Collections.binarySearch(_conversations, id);
            _rwl.readLock().release();
        }
        return valueReturned;
    }
    
    /*
    public Sync readLock() {
        return _rwl.readLock();
    }
    */
    private class Listener implements ConversationListener {
        
        public void conversationAdded(ConversationEvent evt) {
        	Boolean writeLocked = Boolean.FALSE;
            ConversationID id = evt.getConversationID();
            if (! shouldFilter(id)) {
                    int index = getIndexOfConversation(id);
                    if (index < 0) {
                        index = -index - 1;
                        try {
                        _rwl.writeLock().acquire();
                        writeLocked = Boolean.TRUE;
                        } catch (InterruptedException ie) {
                            // _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
                        }
                        if (writeLocked) {
                        _conversations.add(index, id);
                        _rwl.writeLock().release();
                        fireConversationAdded(id, index);
                        }
                    }
            }
        }
        
        public void conversationChanged(ConversationEvent evt) {
        	Boolean writeLocked = Boolean.FALSE;
            ConversationID id = evt.getConversationID();
            int index = getIndexOfConversation(id);
            if (shouldFilter(id)) {
                if (index > -1) {
                    try {
                        _rwl.writeLock().acquire();
                        writeLocked = Boolean.TRUE;
                    } catch (InterruptedException ie) {
                        // _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
                    }
                    if (writeLocked) {
                        _conversations.remove(index);
                        _rwl.writeLock().release();
                        fireConversationRemoved(id, index);
                    }
                }
            } else {
                if (index < 0) {
                    index = -index -1;
                    try {
                        _rwl.writeLock().acquire();
                        writeLocked = Boolean.TRUE;
                    } catch (InterruptedException ie) {
                        // _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
                    }
                    if (writeLocked) {
                        _conversations.add(index, id);
                        _rwl.writeLock().release();
                        fireConversationAdded(id, index);
                    }
                }
            }
        }
        
        public void conversationRemoved(ConversationEvent evt) {
        	Boolean writeLocked = Boolean.FALSE;
            ConversationID id = evt.getConversationID();
            int index = getIndexOfConversation(id);
            if (index > -1) {
                try {
                    _rwl.writeLock().acquire();
                    writeLocked = Boolean.TRUE;
                } catch (InterruptedException ie) {
                    // _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
                }
                if (writeLocked) {
                    _conversations.remove(index);
                    _rwl.writeLock().release();
                    fireConversationRemoved(id, index);
                }
            }
        }
        
        public void conversationsChanged() {
            updateConversations();
        }
        
    }
    
}
