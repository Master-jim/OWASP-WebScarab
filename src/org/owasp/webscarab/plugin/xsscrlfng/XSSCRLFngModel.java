package org.owasp.webscarab.plugin.xsscrlfng;

import java.util.Set;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.logging.Logger;
import java.util.NoSuchElementException;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.ConversationModel;
import org.owasp.webscarab.model.FilteredConversationModel;
import org.owasp.webscarab.model.FrameworkModel;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.plugin.AbstractPluginModel;

import java.net.MalformedURLException;

//2011-01-25 - JLS - Adding support of multiline for injected values - BEGIN
import org.owasp.webscarab.util.MultiLineString;
//2011-01-25 - JLS - Adding support of multiline for injected values - END

// 2011-01-25 - JLS - Adding support for tagging information to a Request, when Conversation ID has not been defined yet - BEGIN
import java.util.HashMap;
// 2011-01-25 - JLS - Adding support for tagging information to a Request, when Conversation ID has not been defined yet - END

// 2011-07-07 - JLS - Adding conversation to model BEFORE doing operations on it - BEGIN
/*
import org.owasp.webscarab.ui.swing.UrlFilteredConversationModel;
import java.util.List;
import EDU.oswego.cs.dl.util.concurrent.Sync;
import java.util.ArrayList;
*/
// 2011-07-07 - JLS - Adding conversation to model BEFORE doing operations on it - END

// 2011-07-29 - JLS - Support of number of requests sent and analyzed - BEGIN
import java.util.concurrent.atomic.AtomicInteger;
import java.util.Timer;
import java.util.TimerTask;
// 2011-07-29 - JLS - Support of number of requests sent and analyzed - END

/**
*
* @author jeremylebourdais
*/
public class XSSCRLFngModel extends AbstractPluginModel {
	
	private FrameworkModel _model;
	// 2011-07-07 - JLS - Adding conversation to model BEFORE doing operations on it - BEGIN
	private ConversationModel _conversationModel, _suspectedConversationModel;
	//private XSSVulnerableFilteredConversationModel _conversationModel;
	//private FilteredConversationModel _suspectedConversationModel;
	// 2011-07-07 - JLS - Adding conversation to model BEFORE doing operations on it - END
        
	private LinkedList toBeAnalyzedQueue = new LinkedList();
	
	private Set testedURLandParameterpairs = new HashSet();
	// 2011-01-25 - JLS - Adding support for tagging information to a Request, when Conversation ID has not been defined yet - BEGIN
	private HashMap testedRequestsAndValuesInjected = new HashMap();
	// 2011-01-25 - JLS - Adding support for tagging information to a Request, when Conversation ID has not been defined yet - END
	
	private boolean DEBUG = true;
	
	private Logger _logger = Logger.getLogger(getClass().getName());
	
	private String xssTestString = null;
	// List of characters to be tested
	// 2011-12-02 - JLS - Change default pattern to avoid deletion by JSON filters - BEGIN
	//private String[] injectionCharactersString = {"'",";","!","--","\"","\\","<","O","N","X",">","=","&","{","(",")","}"};
	private String[] injectionCharactersString = {"'",";","--","\"","\\","<","O","N","X",">","=","&"};
	// 2011-12-02 - JLS - Change default pattern to avoid deletion by JSON filters - END
	
	private String crlfTestString = "%0d%0aWebscarabXSSCRLFTest:%20OK%0d%0a";
	private String crlfInjectedHeader="WebscarabXSSCRLFTest";
	
	private HashSet urlAndParametersTested = new HashSet();
	private String urlSeparator = "?";
	
	// 2011-01-21 - JLS - Adding some string definitions - BEGIN
	private String tagParameterVulnerable = "XSSng-Parameter-Vulnerable";
	private String tagParameterVulnerableInjected = "XSSng-Parameter-Vulnerable-Injected";
	private String tagParameterTriedName = "XSSng-Parameter-Tried-Name";
	private String tagParameterTriedValue = "XSSng-Parameter-Tried-Value";
	// 2011-01-21 - JLS - Adding some string definitions - END
	
	
	// 2011-07-29 - JLS - Support of number of requests sent and analyzed - BEGIN
	private AtomicInteger numberOfRequestsSent = null;
	private AtomicInteger numberOfRequestsAnalyzed = null;
	// 2011-07-29 - JLS - Support of number of requests sent and analyzed - END
	
	// 2011-07-07 - JLS - Adding conversation to model BEFORE doing operations on it - BEGIN

/* 	private class XSSVulnerableFilteredConversationModel extends FilteredConversationModel {
		
		private ConversationModel _model;
		private HttpUrl _url = null;
		private List _conversations = new ArrayList();

		public XSSVulnerableFilteredConversationModel(FrameworkModel model, ConversationModel cmodel) {
			super(model, cmodel);
			_model = cmodel;
		}
		
		public boolean shouldFilter(ConversationID id) {
			if (_url == null) {
				return false;
			} else {
				// 2011-06-22 - JLS - Modify filter to include all child requests (code from newer GIT) - BEGIN
				//return ! _url.equals(_model.getRequestUrl(id));
				String cmp1 = _url.toString();
				String cmp2 = _model.getRequestUrl(id).toString();
				return !cmp2.startsWith(cmp1);
				// 2011-06-22 - JLS - Modify filter to include all child requests (code from newer GIT) - END
			}
		}
		void addConversation(ConversationID id) {
			try {
				_rwl.writeLock().acquire();
				int index = _conversations.size();
				_conversations.add(id);
				_rwl.readLock().acquire();
				_rwl.writeLock().release();
				fireConversationAdded(id, index);
				_rwl.readLock().release();
			} catch (InterruptedException ie) {
				_logger.severe("Interrupted! " + ie);
			}
		}
		
		void clear() {
			try {
				_rwl.writeLock().acquire();
				_conversations.clear();
				_rwl.readLock().acquire();
				_rwl.writeLock().release();
				fireConversationsChanged();
				_rwl.readLock().release();
			} catch (InterruptedException ie) {
				_logger.severe("Interrupted! " + ie);
			}
		}

		public ConversationID getConversationAt(int index) {
			return (ConversationID) _conversations.get(index);
		}

		public int getIndexOfConversation(ConversationID id) {
			return _conversations.indexOf(id);
		}
		
		public Sync readLock() {
			return _rwl.readLock();
		}
		
		public int getConversationCount() {
			return _conversations.size();
		}
	} */
	// 2011-07-07 - JLS - Adding conversation to model BEFORE doing operations on it - END

	// 2011-07-29 - JLS - Support of number of requests sent and analyzed - BEGIN
	private final Runnable doShowStatistics = new Runnable() {
		public void run() {
			_logger.fine("Statistics about XSSng requests: ");
			_logger.fine("Requests sent: " + numberOfRequestsSent.get());
			_logger.fine("Requests analyzed: " + numberOfRequestsAnalyzed.get());
			_logger.fine("Percentage done: " + getPercentageDone() + "%.");
		}
	};
	
	TimerTask doShowStatisticsTimerTask = new TimerTask() {
		public void run() {
			java.awt.EventQueue.invokeLater(doShowStatistics);
		}
	};
	private Timer statisticsTimer = new Timer();
	// 2011-07-29 - JLS - Support of number of requests sent and analyzed - END
	
	
	/** Creates a new instance of ExtensionsModel */
	public XSSCRLFngModel(FrameworkModel model) {
		_model = model;
		xssTestString = getStringOfCharacters() ;
		_logger.fine("Injection characters: " + xssTestString);

		/*
		* lower table with possibly vulnerable URLs
		*/
		// 2011-07-07 - JLS - Adding conversation to model BEFORE doing operations on it - BEGIN
		//_conversationModel = new XSSVulnerableFilteredConversationModel(model, model.getConversationModel());
		_conversationModel = new FilteredConversationModel(model, model.getConversationModel()) {
			public boolean shouldFilter(ConversationID id) {
				return !isXSSVulnerable(id);
			}
		};
		// 2011-07-07 - JLS - Adding conversation to model BEFORE doing operations on it - BEGIN

		
		/*
		* upper table with suspected URLs             
		*/
		_suspectedConversationModel = new FilteredConversationModel(model, model.getConversationModel()) {
			public boolean shouldFilter(ConversationID id) {
				return !isXSSTested(id);
			}
		};
		// 2011-07-29 - JLS - Support of number of requests sent and analyzed - BEGIN
		numberOfRequestsSent = new AtomicInteger();
		numberOfRequestsAnalyzed = new AtomicInteger();
		statisticsTimer.schedule(doShowStatisticsTimerTask, 1000, 10000);
		// 2011-07-29 - JLS - Support of number of requests sent and analyzed - END
	}
	
	public ConversationModel getVulnerableConversationModel() {
		return _conversationModel;
	}
	
	public ConversationModel getSuspectedConversationModel() {
		return _suspectedConversationModel;
	}           
	// 2011-07-29 - JLS - Support of number of requests sent and analyzed - BEGIN
	public int getPercentageDone() {
		int percentage = 100;
		if (numberOfRequestsSent.get() > 0) {
			percentage = 100 * numberOfRequestsAnalyzed.get() / numberOfRequestsSent.get();
		}
		return (percentage);
	}
	// 2011-07-29 - JLS - Support of number of requests sent and analyzed - END
	
	public void markAsXSSTested(ConversationID id, HttpUrl url, String location, String parameter) {
		_model.addConversationProperty(id, "XSSng-tested", parameter);
		_model.addUrlProperty(url, "XSSng-tested", location+"/"+parameter);
		try {
			HttpUrl urlWithNoParameters = new HttpUrl (url.getSHPP()) ;
			_logger.fine("Marking URL: "+urlWithNoParameters+" with parameter: "+location+"/"+parameter);
			// 2011-03-15 - JLS - Adding the location in the form: LOCATION/Parameter - BEGIN
			_model.addUrlProperty(urlWithNoParameters, "XSSng-tested", location+"/"+parameter);
			// 2011-03-15 - JLS - Adding the location in the form: LOCATION/Parameter - END
			//urlAndParametersTested.add (urlWithNoParameters.getSHPP()+urlSeparator+parameter);
		} catch (MalformedURLException exception) {
			_logger.info("Error while getting url from "+url);
		}
	}
	
	// 2011-07-07 - JLS - Adding conversation to model BEFORE doing operations on it - BEGIN
	/*public void addConversation(ConversationID id) {
		_conversationModel.addConversation(id);
	}
	*/
	// 2011-07-07 - JLS - Adding conversation to model BEFORE doing operations on it - END

	
	public boolean hasBeenXSSTested(ConversationID id) {
		boolean tested = false;
		tested = hasBeenXSSTested (_conversationModel.getRequest(id).getURL()); 
		return (tested);
	}
	// 2011-07-07 - JLS - Handling SHPP URLs - BEGIN 
	public boolean hasBeenXSSTested(String url, String parameter) {
		boolean tested = false;
		try {
			HttpUrl urlWithNoParameters = new HttpUrl (url) ;
			tested = hasBeenXSSTested(urlWithNoParameters, parameter);
		} catch (MalformedURLException exception) {
			_logger.info("Error while getting url from "+url);
		}
		return tested;
	}
	
	public boolean hasBeenXSSTested(String url, String parameter, String location) {
		boolean tested = false;
		try {
			HttpUrl urlWithNoParameters = new HttpUrl (url) ;
			tested = hasBeenXSSTested(urlWithNoParameters, parameter, location);
		} catch (MalformedURLException exception) {
			_logger.info("Error while getting url from "+url);
		}
		return tested;
	}

	// 2011-07-07 - JLS - Handling SHPP URLs - END
	
	public boolean hasBeenXSSTested(HttpUrl url, String parameter) {
		boolean tested = false;
		try {
			HttpUrl urlWithNoParameters = new HttpUrl (url.getSHPP()) ;
			_logger.fine("Verifying URL: "+urlWithNoParameters+" with parameter: "+parameter);
			String parametersTested = _model.getUrlProperty(urlWithNoParameters, "XSSng-tested");
			if (parametersTested != null) {
				_logger.fine("Parameters tested of url: "+urlWithNoParameters+" : "+parametersTested);
				tested = (parametersTested.indexOf(parameter) > -1);
			}
		} catch (MalformedURLException exception) {
			_logger.info("Error while getting url from "+url);
		}
		return tested;
	}

	// 2011-03-15 - JLS - Adding a method with location testing - BEGIN
	public boolean hasBeenXSSTested(HttpUrl url, String parameter, String location) {
		boolean tested = false;
		try {
			HttpUrl urlWithNoParameters = new HttpUrl (url.getSHPP()) ;
			_logger.fine("Verifying URL: "+urlWithNoParameters+" with parameter: "+parameter);
			String parametersTested = _model.getUrlProperty(urlWithNoParameters, "XSSng-tested");
			if (parametersTested != null) {
				_logger.fine("Parameters tested of url: "+urlWithNoParameters+" : "+parametersTested);
				tested = (parametersTested.indexOf(location+"/"+parameter) > -1);
			}
		} catch (MalformedURLException exception) {
			_logger.info("Error while getting url from "+url);
		}
		return tested;
	}
	// 2011-03-15 - JLS - Adding a method with location testing - END
	
	public boolean hasBeenXSSTested(HttpUrl url) {
		boolean tested = false;
		try {
			HttpUrl urlWithNoParameters = new HttpUrl (url.getSHPP()) ;
			_logger.finest("Verifying URL only: "+urlWithNoParameters);
			tested = (_model.getUrlProperty(urlWithNoParameters, "XSSng-tested") != null);
		} catch (MalformedURLException exception) {
			_logger.info("Error while getting url from "+url);
		}
		
		return tested;
	}

	public boolean isXSSTested(ConversationID id) {
		boolean tested = false;
		tested = (_model.getConversationProperty(id, "XSSng-tested") != null);
		return tested;
	}
	
	public String getXSSTested(ConversationID id) {
		String params = _model.getConversationProperty(id, "XSSng-tested");
		if (params != null) return params;
		return _model.getConversationProperty(id, "XSSng-tested");
	}
	
	// 2011-01-21 - JLS - Adding getXSSParamVulnerable to indicate which parameter has been found vulnerable - BEGIN
	public String getXSSParamVulnerable(ConversationID id) {
		String param = _model.getConversationProperty(id, tagParameterVulnerable);
		if (param != null) {
			return param;
		} else {
			return null;
		}
	}
	// 2011-01-21 - JLS - Adding getXSSParamVulnerable to indicate which parameter has been found vulnerable - END

	// 2011-03-15 - JLS - Adding getXSSParamTested to know which parameter has been tested - BEGIN
	public String getXSSParamTested(ConversationID id) {
		String param = _model.getConversationProperty(id, tagParameterTriedName);
		if (param != null) {
			return param;
		} else {
			return null;
		}
	}
	// 2011-03-15 - JLS - Adding getXSSParamTested to know which parameter has been tested - END
	
	
	public void setXSSValueTried (ConversationID id) {
	String [] valueTried = (String []) testedRequestsAndValuesInjected.get(getRequest(id));
		if (valueTried != null) {
			// 2011-03-14 - JLS - Modifying add to set - BEGIN
			_model.setConversationProperty(id, tagParameterTriedName, valueTried[0]);
			_model.setConversationProperty(id, tagParameterTriedValue, valueTried[1]);
			// 2011-03-14 - JLS - Modifying add to set - END
		}
	}
	// 2011-01-21 - JLS - Adding setXSSVulnerableParameter to indicate which parameter has been found vulnerable - BEGIN
	public void setXSSVulnerableParameter(ConversationID id, HttpUrl url, String parameter, String injectedValue) {
		// 2011-03-14 - JLS - Modifying add to set (only one value, so scratched when called again) - BEGIN
		// 2011-06-21 - JLS - TODO: modify to handle properly the different cases (one parameter or several) and to be sure they are correctly displayed then.
		_model.addConversationProperty(id, tagParameterVulnerable, parameter);
		_model.addConversationProperty(id, tagParameterVulnerableInjected, injectedValue);
		_model.addUrlProperty(url, tagParameterVulnerable, parameter);
		_model.addUrlProperty(url, tagParameterVulnerableInjected, parameter);
		// 2011-03-14 - JLS - Modifying add to set (only one value, so scratched when called again) - END
		try {
			HttpUrl urlWithNoParameters = new HttpUrl (url.getSHPP()) ;
			_logger.finest("Marking URL: "+urlWithNoParameters+" vulnerable with parameter: "+parameter);
			_model.addUrlProperty(urlWithNoParameters, tagParameterVulnerable, parameter);
		} catch (MalformedURLException exception) {
			_logger.info("Error while getting url from "+url);
		}
	}
	// 2011-01-21 - JLS - Adding setXSSVulnerableParameter to indicate which parameter has been found vulnerable - END
	
	// 2011-01-21 - JLS - Adding getXSSParamVulnerableInjected to indicate which parameter has been found vulnerable - BEGIN
	public String getXSSParamVulnerableInjected(ConversationID id) {
		MultiLineString multiTemp = new MultiLineString();
		String param = _model.getConversationProperty(id, tagParameterVulnerableInjected);
		if (param != null) {
			return param.replaceAll(", ",multiTemp.defaultSeparator);
		} else {
			return null;
		}
	}
	// 2011-01-21 - JLS - Adding getXSSParamVulnerableInjected to indicate which parameter has been found vulnerable - END
	
	public boolean isCRLFSuspected(ConversationID id) {
		boolean suspect = false;
		suspect |= (_model.getConversationProperty(id, "CRLFng-GET") != null);
		suspect |= (_model.getConversationProperty(id, "CRLFng-POST") != null);
		return suspect;
	}
	
	public String getCRLFSuspected(ConversationID id) {
		String params = _model.getConversationProperty(id, "CRLFng-GET");
		if (params != null) return params;
		return _model.getConversationProperty(id, "CRLFng-POST");
	}
	public boolean isSuspected(HttpUrl url) {
		boolean suspect = false;
		suspect |= (_model.getUrlProperty(url, "XSSng-GET") != null);
		suspect |= (_model.getUrlProperty(url, "XSSng-POST") != null);
		suspect |= (_model.getUrlProperty(url, "CRLFng-GET") != null);
		suspect |= (_model.getUrlProperty(url, "CRLFng-POST") != null);
		return suspect;
	}
	
	public void setCRLFVulnerable(ConversationID id, HttpUrl url) {
		_model.setUrlProperty(url, "CRLFng", "TRUE");
		_model.setConversationProperty(id, "CRLFng", "TRUE");
	}
	
	public boolean isCRLFVulnerable(ConversationID id) {
		return "TRUE".equals(_model.getConversationProperty(id, "CRLFng"));
	}
	
	public boolean isCRLFVulnerable(HttpUrl url) {
		return "TRUE".equals(_model.getUrlProperty(url, "CRLFng"));
	}
	
	public void setXSSVulnerable(ConversationID id, HttpUrl url) {
		_model.setUrlProperty(url, "XSSng", "TRUE");
		_model.setConversationProperty(id, "XSSng", "TRUE");
	}
	
	// 2011-03-15 - JLS - Adding a flag to know if a XSS vulnerability has been found or not - BEGIN
	public void unsetXSSVulnerable(ConversationID id, HttpUrl url) {
		_model.setUrlProperty(url, "XSSng", "FALSE");
		_model.setConversationProperty(id, "XSSng", "FALSE");
	}
	// 2011-03-15 - JLS - Adding a flag to know if a XSS vulnerability has been found or not - BEGIN


	public boolean isXSSVulnerable(ConversationID id) {
		return "TRUE".equals(_model.getConversationProperty(id, "XSSng"));
	}
	
	public boolean isXSSVulnerable(HttpUrl url) {
		return "TRUE".equals(_model.getUrlProperty(url, "XSSng"));
	}
	
	public String[] getCRLFSuspiciousParameters(ConversationID id, String where) {
		return _model.getConversationProperties(id, "CRLFng-"+where);
	}
	
	public String[] getXSSSuspiciousParameters(ConversationID id, String where) {
		return _model.getConversationProperties(id, "XSSng-"+where);
	}
	
	public String getXSSTestString() {
		return xssTestString;
	}

	// 2011-07-08 - JLS - Adding multiple injection tokens - BEGIN
	public String getXSSTestStrings() {
		return xssTestString;
	}
	// 2011-07-08 - JLS - Adding multiple injection tokens - END

	public void setXSSTestString(String _xssTestString) {
		if (_xssTestString != null) {
			xssTestString = _xssTestString;
		}
	}
	
	public String getCRLFTestString() {
		return crlfTestString;        
	}
	
	public void setCRLFTestString(String _crlfTestString) {
		crlfTestString = _crlfTestString;
	}
	
	public String getCRLFInjectedHeader() {
		return crlfInjectedHeader;
	}
	
	public void setCRLFInjectedHeader(String _crlfInjectedHeader) {
		crlfInjectedHeader = _crlfInjectedHeader;
	}
	
	public Request getRequest(ConversationID id) {
		return _model.getRequest(id);
	}
	
	public Response getResponse(ConversationID id) {
		return _model.getResponse(id);
	}
	
	private boolean isTested(Request req, String vulnParam, String value) {
		HttpUrl url = req.getURL();
		return testedURLandParameterpairs.contains(url.getSHPP()+vulnParam+value);
	}
		
	public void enqueueRequest(Request req, String paramName, String value) {
		synchronized(toBeAnalyzedQueue) {
			// 2011-07-27 - JLS - Modifying behavior to launch request without testing if already tested (already handled in plugin) - BEGIN
			/*
			if (!isTested(req, paramName, value)) {
				toBeAnalyzedQueue.addLast(req);
				toBeAnalyzedQueue.notifyAll();
				testedURLandParameterpairs.add(req.getURL().getSHPP()+paramName+value);
				String [] tempTable = new String[2];
				tempTable[0] = paramName;
				tempTable[1] = value;
				testedRequestsAndValuesInjected.put(req,tempTable);
			}
			*/
			toBeAnalyzedQueue.addLast(req);
			toBeAnalyzedQueue.notifyAll();
			testedURLandParameterpairs.add(req.getURL().getSHPP()+paramName+value);
			String [] tempTable = new String[2];
			tempTable[0] = paramName;
			tempTable[1] = value;
			testedRequestsAndValuesInjected.put(req,tempTable);
			numberOfRequestsSent.addAndGet(1);
			// 2011-07-27 - JLS - Modifying behavior to launch request without testing if already tested (already handled in plugin) - END
		}
	}
	
	public void oneMoreRequestAnalyzed() {
		numberOfRequestsAnalyzed.addAndGet(1);
	}
	public boolean hasMoreRequests() {
		synchronized (toBeAnalyzedQueue) {
			return(!toBeAnalyzedQueue.isEmpty());
		}
	}
	
	public boolean allRequestsAnalyzed() {
		return ((numberOfRequestsAnalyzed.get() - numberOfRequestsSent.get()) == 0);
	}
	public Request dequeueRequest() {
		synchronized (toBeAnalyzedQueue) {
			try {
				while (toBeAnalyzedQueue.isEmpty()) {
					toBeAnalyzedQueue.wait();
				}
				return (Request)toBeAnalyzedQueue.removeFirst();
				
			}
			catch (InterruptedException e) {
				return null;
			}
			catch(NoSuchElementException e) {
				return null;
			}
		}
	}
	
	public String getStringOfCharacters() {
		StringBuffer result = new StringBuffer();
		if (injectionCharactersString.length > 0) {
			result.append(injectionCharactersString[0]);
			for (int i=1; i<injectionCharactersString.length; i++) {
				result.append(injectionCharactersString[i]);
			}
		}
		return result.toString();
    	}
    	
    	// JLS - 2010-07-21 - Adding actions
    	public ConversationModel getConversationModel() {
    		return _model.getConversationModel();
    	}
    	
	public static void main(String[] args) {
		XSSCRLFngModel xssmodel = new XSSCRLFngModel(new FrameworkModel());
		System.out.println("Injection characters: " + xssmodel.getXSSTestString());
	}
	
	// 2011-03-14 - JLS - Getting conversation Origin - BEGIN
	public String getConversationOrigin(ConversationID id) {
		return _model.getConversationOrigin(id);
	}
	// 2011-03-14 - JLS - Getting conversation Origin - END
	
	
	

}
