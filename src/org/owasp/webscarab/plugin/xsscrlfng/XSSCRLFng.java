package org.owasp.webscarab.plugin.xsscrlfng;


import java.io.IOException;
import java.util.logging.Logger;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.StoreException;
import org.owasp.webscarab.plugin.Framework;
import org.owasp.webscarab.plugin.Hook;
import org.owasp.webscarab.plugin.Plugin;
import org.owasp.webscarab.httpclient.FetcherQueue;
import org.owasp.webscarab.httpclient.ConversationHandler;
import org.owasp.webscarab.model.NamedValue;
import org.owasp.webscarab.util.Encoding;
import java.net.MalformedURLException;
import java.util.Iterator;
import org.owasp.webscarab.model.Preferences;
import java.util.ArrayList;

/**
*
* @author jeremylebourdais
*/
public class XSSCRLFng implements Plugin, ConversationHandler {
	
	private final Framework framework;
	private final XSSCRLFngModel model;
	private final static Logger LOGGER = Logger.getLogger(XSSCRLFng.class.getName());

	// Number of threads to use
	private final static int THREADS = 8;
	// Delay for threads
	private final static int DELAY = 100;
	// TODO Move these fields to the model
	private final static String MODEL_STATUS_STARTED = "Started";
	private final static String MODEL_STATUS_STOPPED = "Stopped";
	
	// Regexp of acceptable Content-Type
	private final static String ACCEPTABLE_CONTENT_TYPE = "(text/.*|application/x-javascript.*|application/json.*)";
	
	// Tells if the plugin is currently testing all requests made by WebScarab. Else it will only test requests asked by the user.
	private Boolean isTestingAllRequests = Boolean.FALSE;
	
	// Perform or not SQLi tests
	//private Boolean performSQLiTests = Boolean.TRUE;
	
	// Perimeter URL of the target
	private String _urlOfTarget = null;
	
	private final TokenGenerator tokenGenerator;
	private final static ConfigurationHolder configuration = new ConfigurationHolder();
	
	private final static String HEADER_PARAMETER_TESTED = "XSSng-Parameter-Tested";
	private final static String HEADER_ORIGINAL_REQUESTID = "XSSng-Original-RequestId";
	
	private final static String PREFERENCE_PROPERTY_URLFILTER = "XSSng.urlfilter";

	/** Creates a new instance of XSSCRLF
	* @param framework Framework of WebScarab to use
	*/
	public XSSCRLFng(final Framework framework) {
		if (null == framework) {
			LOGGER.severe("Constructor with a null parameter, initialization not done.");
		}
			this.framework = framework;
			model = new XSSCRLFngModel(framework.getModel());
			tokenGenerator = new TokenGenerator(configuration);
			
		_urlOfTarget = Preferences.getPreference(PREFERENCE_PROPERTY_URLFILTER, "");
		LOGGER.info ("Configured to perform tests on URL: " + _urlOfTarget);
	}
	
	/** The plugin name
	* Herited from org.owasp.webscarab.plugin.Plugin 
	* @return The name of the plugin
	*/
	@Override
	public String getPluginName() {
		return "XSS/CRLF ng";
	}
	
	/**
	* informs the plugin that the Session has changed
	* Herited from org.owasp.webscarab.plugin.Plugin 
	* 
	*/
	@Override
	public void setSession(String type, Object store, String session) throws StoreException {
		// No session is used for the moment
	}
	
	/**
	* starts the plugin
	* Herited from org.owasp.webscarab.plugin.Plugin 
	*/
	@Override
	public void run() {
		Request req = null;
		LOGGER.info("Starting " + getPluginName());
		
		FetcherQueue _fetcherQueue = new FetcherQueue(getPluginName(), this, THREADS, DELAY);
		
		model.setRunning(true);
		model.setStopping(false);
		model.setStatus(MODEL_STATUS_STARTED);
		
		while (!model.isStopping() || model.hasMoreRequests()) {
			req = model.dequeueRequest();
			if (req != null) {
				_fetcherQueue.submit(req);
			}
			req = null;
		}
		LOGGER.info("Stopping " + getPluginName());
		model.setStopping(true);
		model.setRunning(false);
		model.setStatus(MODEL_STATUS_STOPPED);
		LOGGER.info("Status of " + getPluginName() + " is now: " + model.getStatus());
	}
	
	/** called to know if plugin is running or not
	* Herited from org.owasp.webscarab.plugin.Plugin 
	* @return true if plugin is running
	*/
	@Override
	public boolean isRunning() {
		return model.isRunning();
	}

	/** called to test whether the plugin is able to be stopped
	* Herited from org.owasp.webscarab.plugin.Plugin 
	* @return false if the plugin can be stopped
	*/
	@Override
	public boolean isBusy() {
		return model.isBusy();
	}
	
	/** called to determine what the current status of the plugin is
	* Herited from org.owasp.webscarab.plugin.Plugin 
	* @return status of the model (cf. MODEL_STATUS_STOPPED and MODEL_STATUS_STARTED)
	*/
	@Override
	public String getStatus() {
		return model.getStatus();
	}
	
	/**
	* called to suspend or stop the plugin
	* Herited from org.owasp.webscarab.plugin.Plugin 
	* @return false if the pludin is not running
	*/
	@Override
	public boolean stop() {
		LOGGER.info("Asking to stop " + getPluginName());
		// Inform the model to stop
		model.setStopping(true);
		model.setRunning(false);
		return model.isRunning();
	}
	
	/** called to determine whether the data stored within the plugin has been modified and should be saved
	* Herited from org.owasp.webscarab.plugin.Plugin
	* @return true if some data need to be saved
	*/
	@Override
	public boolean isModified() {
		return model.isModified();
	}
	
	/**
	* called to instruct the plugin to flush any memory-only state to the store.
	* Herited from org.owasp.webscarab.plugin.Plugin 
	* @throws StoreException if there is any problem saving the session data
	*/ 
	@Override
	public void flush() throws StoreException {
		// No flush is needed
	}
	
	/** Check if the request/response must be analyzed by the Plugin to do further actions
	* Herited from org.owasp.webscarab.plugin.Plugin 
	* @param id ConversationID to be analyzed
	* @param request Original request to analyze
	* @param response Original response to analyze
	* @param origin Name of the plugin which created this Request/Response
	*/
	@Override
	public void analyse(ConversationID id, Request request, Response response, String origin) {
		//this.analyseForced(id, request, response, origin, Boolean.FALSE);
	}
	
	/** Returns the scripting hooks defined in this plugin
	* Herited from org.owasp.webscarab.plugin.Plugin 
	* @return Array of Hooks
	*/
	@Override
	public Hook[] getScriptingHooks() {
		return new Hook[0];
	}
	
	/** Returns a scriptable Object to be used in Scripted component
	* Herited from org.owasp.webscarab.plugin.Plugin 
	* @return Scriptable object to be used
	*/
	@Override
	public Object getScriptableObject() {
		return null;
	}
	
	/** Called by a FetcherQueue when a response is correctly received
	*   Response received will be related to a Request made by this plugin
	* Herited from org.owasp.webscarab.httpclient.ConversationHandler 
	* @param responseReceived Response received
	**/
	@Override
	public void responseReceived(Response responseReceived) {
		if (responseReceived == null) {
			LOGGER.severe("Null response so it cannot be analyzed. Aborting treatment.");
			return;
		}
		
		Request initiatingRequest = responseReceived.getRequest();
		if (initiatingRequest == null) {
			LOGGER.severe("No request associated with response received. Aborting treatment.");
			return;
		}
		LOGGER.finest("Request associated with the response has been found.");

		LOGGER.fine("Adding conversation to framework.");
		ConversationID id = framework.addConversation(initiatingRequest, responseReceived, getPluginName());
		LOGGER.fine("Conversation added, id is: " + id);
		
		
		LOGGER.fine("Calling analysis methods.");
		
		analyseResponse(responseReceived, Boolean.FALSE, Boolean.TRUE);
		model.oneMoreRequestAnalyzed();
	}
	
	/** Called by a FetcherQueue if an error has been encountered during the treatment of the response of a request.
	* Herited from org.owasp.webscarab.httpclient.ConversationHandler 
	* @param request Request generating an Exception
	* @param ioe Exception thrown during the treatment
	**/
	@Override
	public void requestError(Request request, IOException ioe) {
		if (request == null || ioe == null) {
			LOGGER.severe("Null parameter found, should not happen!");
		}
		LOGGER.warning("Error for the request: " + request);
		LOGGER.warning("Exception was: " + ioe);
	}


	/** Called to analyse again a response, which can be not initiated from this plugin
	*
	* @param responseReceived Response already received which needs to be analyzed again
	**/
	public void analyseAgainResponse(Response responseReceived) {
		if (responseReceived == null) {
			LOGGER.severe("Null response so it cannot be analyzed. Aborting treatment.");
			return;
		}
		
		Request request = responseReceived.getRequest();
		if (request == null) {
			LOGGER.severe ("No request associated with response received. Aborting treatment.");
			return;
		}
		LOGGER.finest("Request associated with the response has been found.");
		
		ConversationID id = responseReceived.getConversationID ();
		if (id == null) {
			LOGGER.severe("Response should have a ConversatioID but it is null!");
			return;
		}
		
		LOGGER.fine("Calling analysis methods.");

		// Must check if it is from plugin as it can be called again and/or later
		Boolean fromPlugin = model.getConversationOrigin(id).equals(getPluginName());
		
		analyseResponse(responseReceived, Boolean.TRUE, fromPlugin);
	}
	
	/** Calls the different modules of analysis on a response
	* @param responseToAnalyse Response either received by the plugin or another
	* @param analyseAgain Ask the modules to analyse again the response even if it has been treated before
	* @param fromPlugin Needed for the modules to know if some parameters specific to this plugin will be found
	**/
	private void analyseResponse(Response responseToAnalyse, Boolean analyseAgain, Boolean fromPlugin) {
		if (responseToAnalyse == null || analyseAgain == null || fromPlugin == null) {
			LOGGER.severe("Null parameter found, leaving!");
			return;
		}
		//checkForXSSInResponse(responseToAnalyse, reAnalyse, fromPlugin);
		//checkForSQLiInResponse(responseToAnalyse, reAnalyse, fromPlugin);
	}

	/** Returns the current XSSCRLFngModel used. It is needed by the XSSCRLFngPanel to be initialized
	* @return Current Model
	**/
	public XSSCRLFngModel getModel() {
		return model;
	}

	/** Tells if the plugin is currently testing all requests made by WebScarab. Else it will only test requests asked by the user.
	* @return True if the plugin is currently testing all requests
	**/
	public Boolean getIsTestingAllRequests() {
		return isTestingAllRequests;
	}
	
	/** Set the behavior of the plugin, to check all requests from WebScarab or only the ones asked by the user
	* @param parameter True if the plugin must analyze all requests
	*/
	public void testAllRequests(Boolean parameter) {
		if (parameter == null) {
			LOGGER.warning("Null parameter found, leaving!");
			return;
		}
		isTestingAllRequests = parameter;
	}
	
	/** Tells if the plugin tests SQL injection or not
	* @return True if the plugin is currently testing for SQLi injections
	**/
	public Boolean isPerformingSQLiTests() {
		// TODO: integrate a link from the panel to the ConfigurationHolder
		return configuration.getPerformSQLiTests();
	}
	
	/** Tells the plugin to tests SQL injection or not
	* @param parameter True if the plugin must test for SQLi injections
	**/
	public void setPerformSQLiTests(Boolean parameter) {
		if (parameter == null) {
			LOGGER.warning("Null parameter found, leaving!");
			return;
		}
		//performSQLiTests = parameter;
		configuration.setPerformSQLiTests(parameter);
	}
	
	/** Define the url of the target 
	* @param filterUrl Filter to define URL of the target, using regexp
	*/
	public void setUrlOfTarget(String filterUrl) {
		if (filterUrl == null) {
			LOGGER.warning("Null parameter found, leaving!");
			return;
		}
		_urlOfTarget = filterUrl;
	}

	/** Returns the url of the target 
	* @return Filter URL of the target, using regexp
	*/
	public String getUrlOfTarget() {
		return (_urlOfTarget);
	}
	
	
	/** Ask the plugin to perform checks on a Conversation. It will perform tests again even if it has been tested before.
	* @param id Conversation id to check for XSS or SQLi 
	*/
	public void checkConversation(ConversationID id) {
		if (id == null) {
			LOGGER.warning("Null parameter found, leaving!");
			return;
		}
		checkConversation(id, Boolean.TRUE);
	}
	

	/** Check whether Content-Type is acceptable to be tested by the plugin
	* @param contentType Value of the Content-Type
	* @return Whether the Content-Type is acceptable or not
	*/
	private Boolean checkContentTypeIsOK(String contentType) {
		// Accept responses without Content-Type as it might be testable
		if (contentType == null || contentType.matches(ACCEPTABLE_CONTENT_TYPE)) {
			LOGGER.finest("Content-Type OK");
			return(true);
		}
		return(false);
	}



	/** Ask the plugin to perform checks on a Conversation. It will perform tests again even if it has been tested before. However, it will not test Conversations generated by the plugin. It is recommended to check only original requests.
	* @param id Conversation id to check for XSS or SQLi 
	*/
	private void checkConversation(ConversationID id, Boolean checkForced) {
		if (id == null || checkForced == null) {
			LOGGER.severe("Error, one or more parameter(s) with null value, aborting analysis.");
			return;
		}
		
		// To avoid tests of tests, do not perform checks on Conversations made by the plugin, except if checkForced
		if (model.getConversationOrigin(id).equals(getPluginName()) && !checkForced) {
			LOGGER.fine("Conversation " + id + " from the plugin, not treated. Please check the original request.");
			return;
		}
		
		Request originalRequest = model.getRequest(id);
		Response originalResponse = model.getResponse(id);
		
		if (originalRequest == null || originalResponse == null) {
			LOGGER.warning("Response or Request is null, leaving.");
			return;
		}

		// is this something we should check? Bypass this test if checkForced
		String contentType = originalResponse.getHeader("Content-Type");
		if (! checkContentTypeIsOK(contentType) && ! checkForced) {
			LOGGER.fine("Conversation "+id+" not containing a usable Content-Type, not treated.");
			return;
		}
		
		byte[] responseContent = originalResponse.getContent();
		if ((responseContent == null || responseContent.length == 0) && !(originalResponse.getStatus().startsWith("3") || originalResponse.getStatus().startsWith("2"))) {
			LOGGER.fine("Response body is null, not treated.");
			return;
		}
			
		// Filtering url to avoid attacks on other domains
		if (! originalRequest.getURL().getHost().matches(_urlOfTarget)) {
			LOGGER.info("Not testing the URL (out of the scope): " + originalRequest.getURL());
			return;
		}		
		
		// Let's check!
		checkGetParametersMultipleTable(id, checkForced);
		checkPageFilename(id, checkForced);
		checkPostParametersMultipleTable(id, checkForced);
	}

	/** Generates requests to test GET parameters
	* Warning: it assumes the ConversationID is correct and that the related Request and Response are valid
	* @param id Original ConversationID
	* @param checkForced True to test the request even if if has been tested before
	**/
	private void checkGetParametersMultipleTable(ConversationID id, Boolean checkForced) {
		if (id == null || checkForced == null) {
			LOGGER.warning("Null parameter found, leaving!");
			return;
		}
		
		Request originalRequest = model.getRequest(id);
		// TODO: test if request have been tested before, and if it's the case, only redo it if checkForced
		if (originalRequest != null) {
			String queryString = originalRequest.getURL().getQuery();
			// Case where POST request has also parameters in URL - BEGIN
			if (queryString != null && queryString.length() > 0) {
				LOGGER.fine ("checkGetParametersMultipleTable for conversation ID: " + id);
				launchCheckGetParametersMultipleTable(id, checkForced);
			}
		}
	}
	
	/** Generates requests to test POST parameters
	* Warning: it assumes the ConversationID is correct and that the related Request and Response are valid
	* @param id Original ConversationID
	* @param checkForced True to test the request even if if has been tested before
	**/
	private void checkPostParametersMultipleTable(ConversationID id, Boolean checkForced) {
		if (id == null || checkForced == null) {
			LOGGER.warning("Null parameter found, leaving!");
			return;
		}
		Request originalRequest = model.getRequest(id);
		// Test POST queries
		if (originalRequest != null && originalRequest.getMethod().equalsIgnoreCase("POST") && checkForced)
		{
			LOGGER.fine ("checkPostParametersMultipleTable for conversation ID: " + id);
			//checkPostParametersMultipleTable(id, originalRequest, checkForced);
		}
	}
	
	/** Generates requests to test the PageFile name
	* Warning: it assumes the ConversationID is correct and that the related Request and Response are valid
	* @param id Original ConversationID
	* @param checkForced True to test the request even if if has been tested before
	**/
	private void checkPageFilename(ConversationID id, Boolean checkForced) {
		if (id == null || checkForced == null) {
			LOGGER.warning("Null parameter found, leaving!");
			return;
		}
		Request originalRequest = model.getRequest(id);
		if (originalRequest != null && originalRequest.getMethod().equalsIgnoreCase("GET") && (isTestingAllRequests || checkForced)) {
			LOGGER.fine ("checkPageFilename for conversation ID: " + id);
			//checkPageFilename(id, originalRequest, checkForced);
		}
	}
	
		
	/** Replaces a parameter value by another in the query string of an url
	* @param queryString Query string (only, not the whole URL) in which to replace the parameter 
	* @param parameterName Name of the parameter to replace
	* @param newParameterValue New value of the parameter
	* @return New query string with the parameter changed
	*/
	private String getParametersWithTestString(String queryString, String parameterName, String newParameterValue) {
		StringBuffer newQuery = new StringBuffer("");
		
		NamedValue[] listOfParameters = NamedValue.splitNamedValues(queryString, "&", "=");
		for (int i=0; i < listOfParameters.length; i++) {
			newQuery.append(listOfParameters[i].getName());
			newQuery.append('=');
			if (listOfParameters[i].getName().equals(parameterName)) {
				newQuery.append(newParameterValue);
			} else {
				newQuery.append(listOfParameters[i].getValue());
			}
			if (i < listOfParameters.length-1) {
				newQuery.append('&');
			}
		}
		return newQuery.toString();
	}
	
	/** Mark a request as tested and adds specific headers in the request sent too. This can be useful for post-analysis.
	* @param originalConversation Id of the original Conversation ID, used to create this new request.
	* @param newRequestToSend Request to send
	* @param locationOfTheParameter Location of the parameter modified in this request (like GET, POST, etc)
	* @param parameterTested Name of the parameter modified
	* @param testType Type of the test (XSS-Test, SQLi-Num, SQLi-Text, etc.)
	*/
	private void markRequestAndOriginalConversationAsTested(ConversationID originalConversation, Request newRequestToSend, String locationOfTheParameter, String parameterTested, String testType) {
		if (originalConversation == null || newRequestToSend == null || locationOfTheParameter == null || parameterTested == null || testType == null) {
			LOGGER.severe("Attempted to mark a request as tested with some null parameters, leaving!");
			LOGGER.fine("Info about parameters: "+ originalConversation + " - " + newRequestToSend + " - " + locationOfTheParameter + " - " + parameterTested + " - " + testType);
			return;
		}
		String parameterAndTestType = parameterTested + "(" + testType + ")";
		model.markRequestAndOriginalConversationAsTested(originalConversation, newRequestToSend, locationOfTheParameter, parameterAndTestType);
		newRequestToSend.addHeader(HEADER_PARAMETER_TESTED, locationOfTheParameter + "/" + parameterAndTestType);
		newRequestToSend.addHeader(HEADER_ORIGINAL_REQUESTID, originalConversation.toString());
	}
	
	
	
	/** Asks the model to send a GET request with one parameter modified
	* @param originalRequest Original request to use as a model to create the new one.
	* @param originalQueryString Original query string to avoid extracting it from the original request again.
	* @param parameterToChange Name of the parameter in the query string to modify
	* @param newParameterValue New value of the parameter
	* @return The Request if it has been correctly created with the crafted URL or null if a error occured during the creation of the URL.
	*/
	private Request sendGetRequest(Request originalRequest, String originalQueryString, String parameterToChange, String newParameterValue) {
		Request newRequest = new Request(originalRequest);
		String originalURL = originalRequest.getURL().getSHPP();
		String newURL = originalURL + "?" + getParametersWithTestString(originalQueryString, parameterToChange, newParameterValue);

		try {
			newRequest.setURL(new HttpUrl (newURL));
		} catch (MalformedURLException exception) {
			// Logger level fine as it is normal to have errors during the creation of some invalid URLs
			LOGGER.fine("Error during the URL creation of: " + newURL);
			LOGGER.finest("Exception was: " + exception);
			return null;
		}
		// Ask to send the request
		model.enqueueRequest(newRequest);
		LOGGER.fine("URL creation succeeded for: " + newURL);
		return newRequest;
	}
	
	
	
	/** Generates requests to test the PageFile name
	* Warning: it assumes the ConversationID is correct and that the related Request and Response are valid
	* @param originalId Original ConversationID
	* @param checkForced True to test the request even if if has been tested before
	**/
	private void launchCheckGetParametersMultipleTable(ConversationID originalId, Boolean checkForced) {
		if (originalId == null || checkForced == null) {
			LOGGER.warning("Null parameter found, leaving!");
			return;
		}
		
		Request originalRequest = model.getRequest(originalId);
		if (originalRequest == null) {
			LOGGER.warning("Original Request is null, leaving!");
			return;
		}
		
		LOGGER.finest("Testing GET parameters of Conversation: " + originalId + " checkForced is: " + checkForced);
		
		// Get the parameters from the URL
		String originalQueryString = originalRequest.getURL().getQuery();
		if (originalQueryString == null || originalQueryString.length() <= 0) {
			LOGGER.fine("URL has no query parameters, leaving.");
			return;
		}
		NamedValue[] originalParameters = NamedValue.splitNamedValues(originalQueryString, "&", "=");
		if (originalParameters == null) {
			LOGGER.info("URL has a query string but without parameters, leaving");
			return;
		}
		
		// List of tokens to test
		String originalURL = originalRequest.getURL().getSHPP();
		if (originalURL == null) {
			LOGGER.warning("Null URL retrieved, leaving!");
			return;
		}
		
		//String currentParameterName = null;
		//String currentParameterValue = null;
		
		// For each parameter found
		for (int i=0; i<originalParameters.length; i++) {
			String currentParameterName  = originalParameters[i].getName();
			
			
			if (currentParameterName != null) {
				// Does the parameter found has already been tested ?
				if (model.hasBeenXSSTested(originalURL, currentParameterName, "GET") && ! checkForced) {
					LOGGER.fine("Not testing Url: " + originalURL + " with parameter: " + currentParameterName + ", it has already been tested.");
				} else {
					LOGGER.fine("Testing Url: "     + originalURL + " with parameter: " + currentParameterName);
					String currentParameterValue = originalParameters[i].getValue();
					ArrayList<Token> listOfTokensToTest = tokenGenerator.generateNewTestTokensTable(currentParameterValue);
					if (listOfTokensToTest != null) {
						Iterator<Token> iteratorListOfTokensToTest = listOfTokensToTest.iterator();
						
						while (iteratorListOfTokensToTest.hasNext()) {
							// Get the token generated to use as value
							Token currentTokenToTest = iteratorListOfTokensToTest.next();
								String currentTokenToTestType = currentTokenToTest.getTokenType();
								String currentTokenToTestValue = currentTokenToTest.getTokenValue();
								if (currentTokenToTest.hasIndex()) {
									currentTokenToTestType += "-" + currentTokenToTest.getTokenTestIndex();
								} 
								LOGGER.fine("Testing parameter: " + currentParameterName + " with value: " + currentTokenToTestValue + " and type is: " + currentTokenToTestType);

								// Create two new urls: one URL-encoded and the second one not

								// URL-encoded request
								// urlEncode encodes spaces in "+", and we prefer "%20"
								String newParameterValue = Encoding.urlEncode(currentTokenToTestValue).replaceAll("\\+","%20");
								Request newRequest = sendGetRequest(originalRequest, originalQueryString, currentParameterName, newParameterValue);
								markRequestAndOriginalConversationAsTested(originalId, newRequest, "GET", currentParameterName, currentTokenToTestType);

								// URL NOT encoded request
								// Use the minimal encoding to avoid bad interpretation in the url
								String newParameterValueNoEncoding = currentTokenToTestValue.replaceAll("&","%26").replaceAll("=","%3d").replaceAll(" ","%20");
								Request newRequestNoEncoding = sendGetRequest(originalRequest, originalQueryString, currentParameterName, newParameterValueNoEncoding);
								markRequestAndOriginalConversationAsTested(originalId, newRequestNoEncoding, "GET", currentParameterName, currentTokenToTestType);
									
						}
					}
				}
			}
			LOGGER.fine("Done testing GET parameters of Conversation: "+originalId);
		}
	}
}
