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
import org.owasp.webscarab.plugin.xsscrlfng.swing.MultiLineString;
//2011-01-25 - JLS - Adding support of multiline for injected values - END

// 2011-01-25 - JLS - Adding support for tagging information to a Request, when Conversation ID has not been defined yet - BEGIN
import java.util.HashMap;
// 2011-01-25 - JLS - Adding support for tagging information to a Request, when Conversation ID has not been defined yet - END


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
	
	private FrameworkModel _model = null;
	// 2011-07-07 - JLS - Adding conversation to model BEFORE doing operations on it - BEGIN
	private ConversationModel _vulnerableConversationModel = null, _testedConversationModel = null;
	// 2011-07-07 - JLS - Adding conversation to model BEFORE doing operations on it - END
        
	private LinkedList<Request> toBeAnalyzedQueue = new LinkedList<Request>();
	
	private Set<String> testedURLandParameterpairs = new HashSet<String>();
	// 2011-01-25 - JLS - Adding support for tagging information to a Request, when Conversation ID has not been defined yet - BEGIN
	private HashMap<Request,String[]> testedRequestsAndValuesInjected = new HashMap<Request,String[]>();
	// 2011-01-25 - JLS - Adding support for tagging information to a Request, when Conversation ID has not been defined yet - END
	
	private Logger _logger = Logger.getLogger(getClass().getName());
	
	private String xssTestString = null;
	// List of characters to be tested
	// 2011-12-02 - JLS - Change default pattern to avoid deletion by JSON filters - BEGIN
	private String[] injectionCharactersString = {"'",";","--","\"","\\","<","O","N","X",">","=","&"};
	// 2011-12-02 - JLS - Change default pattern to avoid deletion by JSON filters - END
	
	// 2011-01-21 - JLS - Adding some string definitions - BEGIN
	private static String tagParameterVulnerable = "XSSng-Parameter-Vulnerable";
	private static String tagParameterVulnerableInjected = "XSSng-Parameter-Vulnerable-Injected";
	private static String tagParameterTriedName = "XSSng-Parameter-Tried-Name";
	private static String tagParameterTriedValue = "XSSng-Parameter-Tried-Value";
	// 2011-01-21 - JLS - Adding some string definitions - END
	
	// 2013-03-07 - JLS - Property used by this plugin - BEGIN
	private static String tagPropertyHasBeenTested = "XSSng-tested";
	private static String tagPropertyIsVulnerable = "XSSng-isVulnerable";
	// 2013-03-07 - JLS - Property used by this plugin - END

	// 2011-07-29 - JLS - Support of number of requests sent and analyzed - BEGIN
	private static AtomicInteger numberOfRequestsSent = new AtomicInteger();
	private static AtomicInteger numberOfRequestsAnalyzed = new AtomicInteger();
	// 2011-07-29 - JLS - Support of number of requests sent and analyzed - END
	

	// 2011-07-29 - JLS - Support of number of requests sent and analyzed - BEGIN
	private final Runnable doShowStatistics = new Runnable() {
		public void run() {
			_logger.finer("Statistics about XSSng requests: ");
			_logger.finer("Requests sent: " + numberOfRequestsSent.get());
			_logger.finer("Requests analyzed: " + numberOfRequestsAnalyzed.get());
			_logger.finer("Percentage done: " + getPercentageDone() + "%.");
		}
	};
	
	TimerTask doShowStatisticsTimerTask = new TimerTask() {
		public void run() {
			java.awt.EventQueue.invokeLater(doShowStatistics);
		}
	};
	private static Timer statisticsTimer = new Timer();
	// 2011-07-29 - JLS - Support of number of requests sent and analyzed - END
	
	
	/** Creates a new instance of ExtensionsModel */
	public XSSCRLFngModel(FrameworkModel model) {
		_model = model;
		xssTestString = getStringOfCharacters() ;
		_logger.fine("Injection characters: " + xssTestString);

		
		// 2011-07-07 - JLS - Adding conversation to model BEFORE doing operations on it - BEGIN
		_vulnerableConversationModel = new FilteredConversationModel(_model, _model.getConversationModel()) {
			public boolean shouldFilter(ConversationID id) {
				return !isXSSVulnerable(id);
			}
		};
		// 2011-07-07 - JLS - Adding conversation to model BEFORE doing operations on it - BEGIN

		
		
		_testedConversationModel = new FilteredConversationModel(_model, _model.getConversationModel()) {
			public boolean shouldFilter(ConversationID id) {
				return !hasBeenXSSTested(id);
			}
		};
		// 2011-07-29 - JLS - Support of number of requests sent and analyzed - BEGIN
		//numberOfRequestsSent = new AtomicInteger();
		//numberOfRequestsAnalyzed = new AtomicInteger();
		statisticsTimer.schedule(doShowStatisticsTimerTask, 1000, 30000);
		// 2011-07-29 - JLS - Support of number of requests sent and analyzed - END
	}
	
	public ConversationModel getVulnerableConversationModel() {
		return _vulnerableConversationModel;
	}
	
	public ConversationModel getTestedConversationModel() {
		return _testedConversationModel;
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
	
	
	
	
	/** Add properties to conversations list and url list.
	* @param originalConversation Id of the original Conversation ID, used to create the new request.
	* @param newRequestSent Request sent
	* @param locationOfTheParameter Location of the parameter modified in this request (like GET, POST, etc)
	* @param parameterAndTestType Name of the parameter modified and type of test performed (XSS-Test, SQLi-Num, SQLi-Text, etc.)
	*/
	public void markRequestAndOriginalConversationAsTested(ConversationID originalConversation, Request newRequestSent, String locationOfTheParameter, String parameterAndTestType) {
		String testInformation = locationOfTheParameter + "/" + parameterAndTestType;
		// TEMPFIX // Suppresssion accès au modèle pour éviter les locks
		_model.addConversationProperty(originalConversation, tagPropertyHasBeenTested, testInformation);
		HttpUrl newRequestSentUrl = newRequestSent.getURL();
		if (newRequestSentUrl != null) {
			_model.addUrlProperty(newRequestSentUrl, tagPropertyHasBeenTested, testInformation);
			// Try to tag the URL only
			
			try {
				HttpUrl newRequestSentUrlWithNoParameters = new HttpUrl(newRequestSentUrl.getSHPP());
				_logger.fine("Marking URL: " + newRequestSentUrlWithNoParameters + " with parameter: " + testInformation);
				_model.addUrlProperty(newRequestSentUrlWithNoParameters, tagPropertyHasBeenTested, testInformation);
			} catch (MalformedURLException exception) {
				_logger.info("Error while getting url from " + newRequestSentUrl);
			}
			
		} else {
			_logger.warning("Null URL found in the request to send, should never happen!");
		}
	}
	
	
	/*
	public void markAsXSSTested(ConversationID id, HttpUrl url, String location, String parameter) {
		String valueToStore = location+"/"+parameter;
		_model.addConversationProperty(id, tagPropertyHasBeenTested, valueToStore);
		_model.addUrlProperty(url, tagPropertyHasBeenTested, valueToStore);
		// Try to tag the URL only
		try {
			HttpUrl urlWithNoParameters = new HttpUrl (url.getSHPP());
			_logger.fine("Marking URL: "+urlWithNoParameters+" with parameter: "+valueToStore);
			// 2011-03-15 - JLS - Adding the location in the form: LOCATION/Parameter - BEGIN
			_model.addUrlProperty(urlWithNoParameters, tagPropertyHasBeenTested, valueToStore);
			// 2011-03-15 - JLS - Adding the location in the form: LOCATION/Parameter - END
		} catch (MalformedURLException exception) {
			_logger.info("Error while getting url from "+url);
		}
	}
	*/
	public boolean hasBeenXSSTested(ConversationID id) {
		if (_model.getConversationProperty(id, tagPropertyHasBeenTested) != null) {
			return (_model.getConversationProperty(id, tagPropertyHasBeenTested).length() > 0);
		}
		return false;
	}

	public boolean hasBeenXSSTested(HttpUrl url) {
		boolean tested = false;
		try {
			HttpUrl urlWithNoParameters = new HttpUrl (url.getSHPP()) ;
			_logger.finest("Verifying URL only: "+urlWithNoParameters);
			tested = (_model.getUrlProperty(urlWithNoParameters, tagPropertyHasBeenTested) != null);
		} catch (MalformedURLException exception) {
			_logger.info("Error while getting url from "+url);
		}
		
		return tested;
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
			String parametersTested = _model.getUrlProperty(urlWithNoParameters, tagPropertyHasBeenTested);
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
			String parametersTested = _model.getUrlProperty(urlWithNoParameters, tagPropertyHasBeenTested);
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
	String [] valueTried = testedRequestsAndValuesInjected.get(getRequest(id));
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
		//MultiLineString multiTemp = new MultiLineString();
		String returnValue = null;

		String param = _model.getConversationProperty(id, tagParameterVulnerableInjected);
		if (null != param) {
			returnValue = param.replaceAll(", ",MultiLineString.getDefaultSeparator());
		}
		return returnValue;
	}
	// 2011-01-21 - JLS - Adding getXSSParamVulnerableInjected to indicate which parameter has been found vulnerable - END
		
	public void setXSSVulnerable(ConversationID id, HttpUrl url) {
		_model.setUrlProperty(url, tagPropertyIsVulnerable, "TRUE");
		_model.setConversationProperty(id, tagPropertyIsVulnerable, "TRUE");
	}
	
	// 2011-03-15 - JLS - Adding a flag to know if a XSS vulnerability has been found or not - BEGIN
	public void unsetXSSVulnerable(ConversationID id, HttpUrl url) {
		_model.setUrlProperty(url, tagPropertyIsVulnerable, "FALSE");
		_model.setConversationProperty(id, tagPropertyIsVulnerable, "FALSE");
	}
	// 2011-03-15 - JLS - Adding a flag to know if a XSS vulnerability has been found or not - BEGIN


	public boolean isXSSVulnerable(ConversationID id) {
		return "TRUE".equals(_model.getConversationProperty(id, tagPropertyIsVulnerable));
	}
	
	public boolean isXSSVulnerable(HttpUrl url) {
		return "TRUE".equals(_model.getUrlProperty(url, tagPropertyIsVulnerable));
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
	
	
	public Request getRequest(ConversationID id) {
		return _model.getRequest(id);
	}
	
	public Response getResponse(ConversationID id) {
		return _model.getResponse(id);
	}
	
	
	public void enqueueRequest(Request req) {
		synchronized(toBeAnalyzedQueue) {
			toBeAnalyzedQueue.addLast(req);
			toBeAnalyzedQueue.notifyAll();
			numberOfRequestsSent.addAndGet(1);
		}
	}
	
	public void enqueueRequest(Request req, String paramName, String value) {
		synchronized(toBeAnalyzedQueue) {
			// 2011-07-27 - JLS - Modifying behavior to launch request without testing if already tested (already handled in plugin) - BEGIN
			toBeAnalyzedQueue.addLast(req);
			toBeAnalyzedQueue.notifyAll();
			// TODO - remove this from enqueuRequest
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
				return toBeAnalyzedQueue.removeFirst();
				
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
		System.out.println("Injection characters: " + xssmodel.getXSSTestStrings());
	}
	
	// 2011-03-14 - JLS - Getting conversation Origin - BEGIN
	public String getConversationOrigin(ConversationID id) {
		return _model.getConversationOrigin(id);
	}
	// 2011-03-14 - JLS - Getting conversation Origin - END
	
	// 2011-12-09 - JLS - Adding a check if response has a Request associated - BEGIN
	// Maybe should be placed in Framwork ??,
	public Request getAssociatedRequest(Response response) {
		if (response == null) {
			return null;
		}
		Request request = response.getRequest();
		// Try via _model
		if (request == null) {
			ConversationID id = response.getConversationID();
			request = getRequest(id);
		}
		return(request);
	}
	// 2011-12-09 - JLS - Adding a check if response has a Request associated - END
	
	

}
