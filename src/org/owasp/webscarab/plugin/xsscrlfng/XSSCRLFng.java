package org.owasp.webscarab.plugin.xsscrlfng;


import java.io.File;
import java.io.IOException;
import java.io.FileReader;
import java.util.logging.Logger;
import java.io.BufferedReader;

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
// JLS - 2010-07-20 Adding multipart support
import org.owasp.webscarab.model.MultiPartContent;
import org.owasp.webscarab.model.Message;
import org.owasp.webscarab.model.GWTRPCRequest;
import java.util.Vector;
import java.util.Iterator;

// JLS - 2011-01-13 - Adding pattern matching for the XSS
import java.util.regex.Pattern;
import java.util.regex.Matcher;
// 2011-01-21 - JLS - Adding the support of a filtering url to avoid attacks on other domains - BEGIN
import org.owasp.webscarab.model.Preferences;
// 2011-01-21 - JLS - Adding the support of a filtering url to avoid attacks on other domains - END


// 2011-02-14 - JLS - Adding a set of parameters/values with a request, to add once the response has been received - BEGIN
import java.util.HashMap;
// 2011-02-14 - JLS - Adding a set of parameters/values with a request, to add once the response has been received - END


//2011-05-17 - JLS - Adding long parameters support for injection - BEGIN
import java.util.Arrays;
//2011-05-17 - JLS - Adding long parameters support for injection - END

// 2011-05-17 - JLS - Filtering results that are the same - BEGIN
import java.util.List;
import java.util.ArrayList;
// 2011-05-17 - JLS - Filtering results that are the same - END
// 2011-07-13 - JLS - Better XSS detection - BEGIN
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.nodes.Node;
import org.jsoup.nodes.TextNode;
import org.jsoup.select.Elements;
// 2011-07-13 - JLS - Better XSS detection - END
import java.util.Map;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicInteger;

import name.fraser.neil.plaintext.diff_match_patch;
import name.fraser.neil.plaintext.diff_match_patch.Diff;
import java.util.LinkedList;

/**
*
* @author jeremylebourdais
*/
public class XSSCRLFng implements Plugin, ConversationHandler {
	
	private Framework _framework;
	private XSSCRLFngModel _model;
	private Logger _logger = Logger.getLogger(getClass().getName());
	private FetcherQueue _fetcherQueue = null;
	private int _threads = 8;
	private int _delay = 100;
	public static int MINLENGTH=3;
	
	// 2011-07-29 - JLS - Adding a token to synchronize flushing - BEGIN
	//private final Boolean isFlushing = Boolean.TRUE;
	// 2011-07-29 - JLS - Adding a token to synchronize flushing - END
	private boolean _testAll = false ;
	
	// 2011-07-26 - JLS - Adding a button for SQLi tests - BEGIN
	private boolean _doSQLiTests = false ;
	// 2011-07-26 - JLS - Adding a button for SQLi tests - END
	
	//private int uniqueId = 0;
	private AtomicInteger uniqueId = null;
	
	// 2011-01-21 - JLS - Adding the pattern to find as a member - BEGIN
	
	private String patternToFindPartial = "";
	private String _headerParameterTested= "XSSng-Parameter-Tested";
	private String headerOriginalRequestId= "XSSng-Original-RequestId";
	private String headerUniqueId = "uniqueId";
	private String headerTypeOfTest = "typeOfTest";
	private String headerTestIndex = "testIndex";
	// 2011-11-22 - JLS - Adding value of the tested parameter - BEGIN
	private String headerInjectedString = "injectedString";
	// 2011-11-22 - JLS - Adding value of the tested parameter - END
	private String injectedParameterSeparator = "#-#";
	private String patternPrefix = "EDW-";
	private String patternSuffix = "_EDW";
	private String patternHtmlTag = "ONX";
	private String patternToFind = patternPrefix+"[0-9]+[';!--\"\\\\<"+patternHtmlTag+">=&{()}]"+patternSuffix;
	// 2011-01-21 - JLS - Adding the pattern to find as a member - END
	
	// 2011-07-15 - JLS - Adding HashMap to pass some conversation parameters - BEGIN
	private Map<Request,HashMap<String,String>> specificParametersOfRequests = null;
	// 2011-07-15 - JLS - Adding HashMap to pass some conversation parameters - END
	
	
	// 2011-01-21 - JLS - Adding the support of a filtering url to avoid attacks on other domains - BEGIN
	private String urlOfTarget = "";
	// 2011-01-21 - JLS - Adding the support of a filtering url to avoid attacks on other domains - END
	
	// 2011-02-14 - JLS - Adding a set of parameters/values with a request, to add once the response has been received - BEGIN
	private HashMap<String,String> requestParameters = new HashMap<String,String> ();
	// 2011-02-14 - JLS - Adding a set of parameters/values with a request, to add once the response has been received - END
	
	private Map<String,Map<String,Response[]>> testedParametersForSQLiAll = null;
	private char charToRepeat = 'A';
	
	/** Creates a new instance of XSSCRLF */
	public XSSCRLFng(Framework framework) {
		_framework = framework;
		_model = new XSSCRLFngModel(framework.getModel());
		// 2011-01-21 - JLS - Adding the partial pattern to find as a member - BEGIN
		// TODO - Put this in the "good fashion" and not directly the characters
		patternToFindPartial = patternPrefix+"[0-9]+(.{0,60}"+patternSuffix+"|.{35})";
		// 2011-01-21 - JLS - Adding the partial pattern to find as a member - END
		_logger.info ("PatternToFindPartial defined is: "+patternToFindPartial);
		final String prop = "XSSng.urlfilter";
		urlOfTarget = Preferences.getPreference(prop, "");
		_logger.info ("Configured to perform tests on URL: "+urlOfTarget);
		// 2011-07-15 - JLS - Adding HashMap to pass some conversation parameters - BEGIN
		specificParametersOfRequests = Collections.synchronizedMap(new HashMap<Request,HashMap<String,String>>());
		testedParametersForSQLiAll = Collections.synchronizedMap(new HashMap<String,Map<String,Response[]>>());
		testedParametersForSQLiAll.put ("SQLi-Text", Collections.synchronizedMap(new HashMap<String,Response[]>()));
		testedParametersForSQLiAll.put ("SQLi-Text2", Collections.synchronizedMap(new HashMap<String,Response[]>()));
		testedParametersForSQLiAll.put ("SQLi-Num", Collections.synchronizedMap(new HashMap<String,Response[]>()));
		testedParametersForSQLiAll.put ("SQLi-Num2", Collections.synchronizedMap(new HashMap<String,Response[]>()));
		uniqueId = new AtomicInteger();
	}
	
	public boolean checkContentTypeOK(String contentType) {
		// 2011-12-09 - JLS - Simplifying the tests and accepting null Content-Type - BEGIN
		// TODO: JLS: modify the behavior to check user defined content types and to check a response if asked by the user, even if there is no content type
		if (contentType == null) {
			return(true);
		}
		
		if (contentType.matches("(text/.*|application/x-javascript.*|application/json.*)")) {
			_logger.finest("Content-Type OK");
			return(true);
		}
		return(false);
		// 2011-12-09 - JLS - Simplifying the tests and accepting null Content-Type - END
	}

	// 2011-07-05 - JLS - Adding methods to access/modifythe XSS url filter - BEGIN
	public void setUrlOfTarget(String url) {
		if (url != null) {
			urlOfTarget = url;
			_logger.finer("Modifying URL of the target for: " + urlOfTarget);
			String prop = "XSSng.urlfilter";
			Preferences.setPreference(prop, urlOfTarget);
		}
	}
	
	public String getUrlOfTarget() {
		return (urlOfTarget);
	}
	// 2011-07-05 - JLS - Adding methods to access/modifythe XSS url filter - END

	// Check if the request/response must be analyzed by the Plugin to do further actions
	public void analyse(ConversationID id, Request request, Response response, String origin) {
		this.analyseForced(id, request, response, origin, Boolean.FALSE);
	}
	
	
	
	// 2011-07-07 - JLS - Modifying order of calls - BEGIN
	// Check if the request/response must be analyzed by the Plugin to do further actions
	public void analyseForced(ConversationID id, Request request, Response response, String origin, Boolean checkForced) {
		if (id == null || request == null || response == null || origin == null || checkForced == null) {
			_logger.severe("Error, one or more parameter(s) with null value, aborting analysis.");
			return;
		}
		// Submit a new test for stressing the parameters
		// _testAll should be set when pentester is browsing and requests are sent by the browser
		// checkForced should be set when the pentester wants to analyse AGAIN a conversation (should be only called by the reAnalyse All button)
		if (_testAll || checkForced) {
			submitXSSngTest(id, request, response, origin, checkForced);
		}
		// TODO
		/*
		if (_testAll) {
			checkForXSSInResponse(response, Boolean.FALSE, Boolean.FALSE);
		}
		*/
	}
	
	
	/* Warning!!
	 DOES NOT TEST:
	 	Responses with no content (except with status beginning with 3)
	 	Responses with a contentTypeHeader
	 
	 
	 */
	public void submitXSSngTest(ConversationID id, Request request, Response response, String origin, Boolean checkForced) {
		if (id == null || request == null || response == null || origin == null || checkForced == null) {
			_logger.severe("Error, one or more parameter(s) with null value, aborting analysis.");
			return;
		}
		
		// If generated by the plugin then return
		// 2011-12-13 - JLS - Return even if forced - BEGIN
		if (_framework.getModel().getConversationOrigin(id).equals(getPluginName())) {
			_logger.fine("Conversation "+id+" from the plugin, not treated.");
			return;
		}
		// 2011-12-13 - JLS - Return even if forced - END
		
		// is this something we should check?
		String contentType = response.getHeader("Content-Type");
		if (! checkContentTypeOK(contentType) && ! checkForced) {
			_logger.fine("Conversation "+id+" not containing a usable Content-Type, not treated.");
			return;
		}
		
		// TODO: JLS: change to check with a dedicated function if there is content or not ?
		byte[] responseContent = response.getContent();
		if ((responseContent == null || responseContent.length == 0) && !(response.getStatus().startsWith("3") || response.getStatus().startsWith("2"))) {
			_logger.fine("Response body is null, not treated");
			return;
		}
		
		// 2011-01-21 - JLS - Adding the support of a filtering url to avoid attacks on other domains - BEGIN
		if (! request.getURL().getHost().matches (urlOfTarget) ) {
			_logger.warning ("Not testing the URL (out of the scope): "+request.getURL());
			return;
		}
		// 2011-01-21 - JLS - Adding the support of a filtering url to avoid attacks on other domains - END
		

		// Check GET queries
		
		if (request.getMethod().equalsIgnoreCase("GET") && (_testAll || checkForced)) {
			// 2011-06-21 - JLS - Adding logger.fine to trace actions - BEGIN
			_logger.fine ("checkGetParameters for conversation ID: "+id);
			// 2011-06-21 - JLS - Adding logger.fine to trace actions - END
			//checkGetParametersMultiple(id, request, checkForced);
			checkGetParametersMultipleTable(id, request, checkForced);
			checkPageFilename(id, request, checkForced);
		}
		// Test POST queries
		if (request.getMethod().equalsIgnoreCase("POST") && (_testAll || checkForced))
		{
			// 2011-06-21 - JLS - Adding logger.fine to trace actions - BEGIN
			_logger.fine ("checkPostParameters for conversation ID: "+id);
			// 2011-06-21 - JLS - Adding logger.fine to trace actions - END
			checkPostParametersMultipleTable(id, request, checkForced);
			// 2010-11-26 - JLS - Case where POST request has also parameters in URL - BEGIN
			String queryString = request.getURL().getQuery();
			if (! (queryString == null || queryString.length() <= 0)) {
				// 2011-06-21 - JLS - Adding logger.fine to trace actions - BEGIN
				_logger.fine ("checkGetParametersMultiple for POST for conversation ID: "+id);
				// 2011-06-21 - JLS - Adding logger.fine to trace actions - END
				//checkGetParametersMultiple(id, request, checkForced);
				checkGetParametersMultipleTable(id, request, checkForced);
			}
			// 2010-11-26 - JLS - Case where POST request has also parameters in URL - END
		}
	}

	
	
	
	// 2011-07-07 - JLS - Modifying order of calls - END
	
	// 2011-07-08 - JLS - Adding multiple injection tokens - BEGIN
	public ArrayList<String> generateNewTestTokens() {
		String tokens[] = _model.getXSSTestStrings().split("\\r?\\n");
		ArrayList<String> newTestTokens = new ArrayList<String>();
		for (int i=0; i<tokens.length;i++) {
			//uniqueId++;
			//newTestTokens.add(patternPrefix+uniqueId+tokens[i]+patternSuffix);
			newTestTokens.add(patternPrefix+uniqueId.addAndGet(1)+tokens[i]+patternSuffix);
		}
		newTestTokens.add(generateLongTestToken(Integer.valueOf(5000)));
		return (newTestTokens);
	}
	// 2011-07-08 - JLS - Adding multiple injection tokens - END



	
	public ArrayList<String[]> generateNewTestTokensTable(final String baseParameter) {
		String baseParameterUsed = baseParameter;
		if (baseParameterUsed == null) {
			baseParameterUsed = "";
		}
		String tokens[] = _model.getXSSTestStrings().split("\\r?\\n");
		String tokenType = "XSS-Test";
		ArrayList<String[]> newTestTokens = new ArrayList<String[]>();
		for (int i=0; i<tokens.length;i++) {
			//uniqueId++;
			//String[] newToken = {tokenType,patternPrefix+uniqueId+tokens[i]+patternSuffix};
			String[] newToken = {tokenType,patternPrefix+uniqueId.addAndGet(1)+tokens[i]+patternSuffix};
			newTestTokens.add(newToken);
			_logger.fine("Token added: "+newToken[1]);
		}
		String[] newToken = {"LongValue", generateLongTestToken(Integer.valueOf(5000))};
		newTestTokens.add(newToken);
		return (newTestTokens);
	}



	//2011-05-17 - JLS - Adding long parameters support for injection - BEGIN
	private String generateLongTestToken(Integer length ) {
		if (length.intValue() < 0) {
			return (null);
		}
		char[] chars = new char[length.intValue()];
		Arrays.fill(chars, charToRepeat);
		// 2011-07-07 - JLS  - Modifying behavior to only use big string - BEGIN
		String newToken = patternPrefix+uniqueId.addAndGet(1)+new String(chars)+patternSuffix;
		// 2011-07-07 - JLS  - Modifying behavior to only use big string - BEGIN
		return (newToken);
	}
	//2011-05-17 - JLS - Adding long parameters support for injection - END



	
	public ArrayList<String[]> generateNewLongTokensTable(String baseParameter) {
		if (baseParameter == null) {
			baseParameter = "";
		}
		String tokens[] = {generateLongTestToken(Integer.valueOf(5000))};
		String tokenType = "LongValue";
		
		ArrayList<String[]> newTestTokens = new ArrayList<String[]>();
		for (int i=0; i<tokens.length;i++) {
			String[] newToken = {tokenType,tokens[i]};
			newTestTokens.add(newToken);
		}
		return (newTestTokens);
	}
	

	private ArrayList<String[]> generateNewNumericSQLiAllTokens(String baseParameter) {
		if (baseParameter == null) {
			baseParameter = "";
		}
		String tokens[] = { " AND 1=2", " AND 2=3", " AND0O", " OR0O"," AND 4=3", " AND 5=5", " OR 7=7", " OR 9=9 OR 10=11", " && 1<2"};
		String tokenType = "SQLi-Num-"+uniqueId.addAndGet(1)+"-";
		ArrayList<String[]> newTestTokens = new ArrayList<String[]>();
		for (int i=0; i<tokens.length;i++) {
			String[] newToken = {tokenType+i,baseParameter+tokens[i],Integer.toString(i)};
			newTestTokens.add(newToken);
			_logger.fine("Token added: "+newToken[1]);
		}
		return (newTestTokens);
	}

	private ArrayList<String[]> generateNewNumericSQLiAllTokensWithoutSQLWords(String baseParameter) {
		if (baseParameter == null) {
			baseParameter = "";
		}
		String tokens[] = { " && 1=2", " && 2=3", " &&0O", " ||0O"," && 4=3", " && 5=5", " || 7=7", " || 9=9 || 10=11", " && 1<2"};
		String tokenType = "SQLi-Num2-"+uniqueId.addAndGet(1)+"-";
		ArrayList<String[]> newTestTokens = new ArrayList<String[]>();
		for (int i=0; i<tokens.length;i++) {
			String[] newToken = {tokenType+i,baseParameter+tokens[i],Integer.toString(i)};
			newTestTokens.add(newToken);
			_logger.fine("Token added: "+newToken[1]);
		}
		return (newTestTokens);
	}
	
	
	
	
	private ArrayList<String[]> generateNewTextSQLiAllTokens(String baseParameter) {
		if (baseParameter == null) {
			baseParameter = "";
		}
		// 2013-03-06 - Modify tokens to detect removing of a class of characters (if all alpha is removed, request will work but no vuln - BEGIN
		//String tokens[] = { "''", "''''", "'", "'''","' AND 'A'='B", "' AND 'C'='C", "' OR 'D'='D", "' OR 'F'='F' OR 'G'='H"};
		String tokens[] = { "''", "''''", "'", "'''","' AND 'A1'='B2", "' AND 'C3'='C3", "' OR 'D4'='D4", "' OR 'F5'='F5' OR 'G6'='H7", "&& 'I8'='I8"};
		// 2013-03-06 - Modify tokens to detect removing of a class of characters (if all alpha is removed, request will work but no vuln - END

		String tokenType = "SQLi-Text-"+uniqueId.addAndGet(1)+"-";
		ArrayList<String[]> newTestTokens = new ArrayList<String[]>();
		for (int i=0; i<tokens.length;i++) {
			String[] newToken = {tokenType+i,baseParameter+tokens[i],Integer.toString(i)};
			newTestTokens.add(newToken);
			_logger.fine("Token added: "+newToken[1]);
		}
		return (newTestTokens);
	}

	
	private ArrayList<String[]> generateNewTextSQLiAllTokensWithoutSQLWords(String baseParameter) {
		if (baseParameter == null) {
			baseParameter = "";
		}
		// 2013-03-06 - Modify tokens to detect removing of a class of characters (if all alpha is removed, request will work but no vuln - BEGIN
		//String tokens[] = { "''", "''''", "'", "'''","' AND 'A'='B", "' AND 'C'='C", "' OR 'D'='D", "' OR 'F'='F' OR 'G'='H"};
		String tokens[] = { "''", "''''", "'", "'''","' && 'A1'='B2", "' && 'C3'='C3", "' || 'D4'='D4", "' || 'F5'='F5' || 'G6'='H7", "&& 'I8'='I8"};
		// 2013-03-06 - Modify tokens to detect removing of a class of characters (if all alpha is removed, request will work but no vuln - END

		String tokenType = "SQLi-Text2-"+uniqueId.addAndGet(1)+"-";
		ArrayList<String[]> newTestTokens = new ArrayList<String[]>();
		for (int i=0; i<tokens.length;i++) {
			String[] newToken = {tokenType+i,baseParameter+tokens[i],Integer.toString(i)};
			newTestTokens.add(newToken);
			_logger.fine("Token added: "+newToken[1]);
		}
		return (newTestTokens);
	}

	
	private String generateNewTestToken() {
		String newToken = patternPrefix+uniqueId.addAndGet(1)+_model.getXSSTestString()+patternSuffix;
		return (newToken);
	}



	// 2011-03-14 - JLS - Adding a text area for the XSS search functions - BEGIN
	public void setXSSPatternToFind (String pattern) {
		if (pattern != null && !pattern.equalsIgnoreCase("")) {
			patternToFind = pattern;
		}
	}
	
	public void setXSSPatternToFindPartial (String pattern) {
		if (pattern != null && !pattern.equalsIgnoreCase("")) {
			patternToFindPartial = pattern;
		}
	}
	public String getXSSPatternToFind () {
		return patternToFind;
	}
	
	public String getXSSPatternToFindPartial () {
		return patternToFindPartial;
	}
	// 2011-03-14 - JLS - Adding a text area for the XSS search functions - END

		// 2011-07-08 - JLS - Adding multiple injection tokens - BEGIN
	private void checkGetParametersMultipleTable(ConversationID id, Request origRequest, Boolean checkForced) {
		_logger.fine("Testing GET parameters of Conversation: "+id+" checkForced is: "+checkForced);
		// 2011-01-21 - JLS - Adding some comments - BEGIN
		
		// Get the parameters from the URL
		String queryString = origRequest.getURL().getQuery();
		if (queryString == null || queryString.length() <= 0) {
			_logger.finest("URL has no query parameters, leaving.");
			return;
		}
		NamedValue[] params = NamedValue.splitNamedValues(queryString, "&", "=");
		
		if (params == null) {
			_logger.info("URL has a query string but without parameters, leaving");
			return;
		}
		
		ArrayList<String[]> newTokens = null;
		String currentURL = null;
		
		// For each parameter found
		for (int i=0; i<params.length; i++) {
			String currentParam = params[i].getName();
			String currentParamValue = params[i].getValue();
			// Does the parameter found has already been tested ?
			currentURL =  new String(origRequest.getURL().getSHPP());
			if (_model.hasBeenXSSTested(currentURL, currentParam, "GET") && ! checkForced) {
				_logger.fine("Not testing Url: "+origRequest.getURL()+" with parameter: "+currentParam+", it has already been tested.");
			} else {
				_logger.fine("Testing Url: "+origRequest.getURL().getSHPP()+" with parameter: "+currentParam);
				requestParameters.put (origRequest.getURL().getSHPP(), currentParam);

				newTokens = generateNewTestTokensTable("");
				// 2011-07-26 - JLS - Adding a button for SQLi tests - BEGIN
				// TODO: put the following in generateNewTestTokensTable
				if (_doSQLiTests) {
					newTokens.addAll(generateNewTextSQLiAllTokens(currentParamValue));
					// TODO: Implement a option for evasion
					//newTokens.addAll(generateNewTextSQLiAllTokensWithoutSQLWords(currentParamValue));
					newTokens.addAll(generateNewNumericSQLiAllTokens(currentParamValue));
					// TODO: Implement a option for evasion
					//newTokens.addAll(generateNewNumericSQLiAllTokensWithoutSQLWords(currentParamValue));
				}
				// 2011-07-26 - JLS - Adding a button for SQLi tests - END
				String[] newToken = null;
				String newTokenType = null;
				String newTokenValue = null;
				String newTokenIndex = null;
				Iterator<String[]> iteratorTokens = newTokens.iterator();
				while (iteratorTokens.hasNext()) {
					
					// Engage the test of the current parameter
					
					// Génération d'un paramètre aléatoire unique
					newToken = iteratorTokens.next();
					newTokenType = newToken[0];
					newTokenValue = newToken[1];
					if (newToken.length == 3) {
						newTokenIndex = newToken[2];
					}
					_logger.fine("Testing parameter: " + currentParam + " with value: " + newTokenValue);
					
					// Préparation de la requête avec le paramètre modifié
					// Create two new url: one URL-encoded and the second one not
					
					// Construction of the URL-encoded request
					//newTokenValue = newTokenValue.replaceAll(" ","%20");
					String testString = Encoding.urlEncode(newTokenValue);
					testString = testString.replaceAll("\\+","%20");
					Request newRequest = new Request(origRequest);
					String newURL = origRequest.getURL().getSHPP()+"?"+getParametersWithTestString(queryString, currentParam, testString);
					_logger.fine("newURL: " + newURL);
					 // Construction of the URL NOT encoded request
					String testStringNoEncoding = newTokenValue.replaceAll("&","%26").replaceAll("=","%3d").replaceAll(" ","%20");
					Request newRequestNoEncoding = new Request(origRequest);
					String newURLNoEncoding = origRequest.getURL().getSHPP()+"?"+getParametersWithTestString(queryString, currentParam, testStringNoEncoding);
					_logger.fine("newURLNoEncoding: " + newURLNoEncoding);

					// Add custom header to know which parameter has been tested
					HashMap<String,String> newParametersOfRequest = new HashMap<String,String>();
					newParametersOfRequest.put(_headerParameterTested, "GET/"+currentParam+"("+newTokenType+")");
					newParametersOfRequest.put(headerOriginalRequestId, id.toString());
					newParametersOfRequest.put(headerUniqueId,Integer.toString(uniqueId.get()));
					newParametersOfRequest.put(headerTypeOfTest,newTokenType);
					if (newTokenIndex != null) {
						newParametersOfRequest.put(headerTestIndex,newTokenIndex);
					}


					// Create the URL objects
					try {
						// Set new URL
						newRequest.setURL(new HttpUrl (newURL));
						synchronized(specificParametersOfRequests) {
							HashMap<String,String> newParametersOfRequestEncoded = new HashMap<String,String>(newParametersOfRequest);
							newParametersOfRequestEncoded.put(headerInjectedString, testString);
							specificParametersOfRequests.put(newRequest,newParametersOfRequest);
						}
						//_logger.fine("URL creation of: "+newURL);
						// 2011-12-09 - JLS - Implement a loop to iterate over newParametersOfRequest to add headers, instead of duplicating code - TODO
						newRequest.addHeader(_headerParameterTested, "GET/"+currentParam+"("+newTokenType+")");
						newRequest.addHeader(headerOriginalRequestId, id.toString());

						// Launch the new created requests
						_model.enqueueRequest(newRequest, currentParam, testString);
						_logger.fine("URL creation succeeded for: "+newURL);
					} catch (MalformedURLException exception) {
						// Logger level fine as it is normal to have errors during the creation of some invalid URLs
						_logger.fine("Error during the URL creation of: "+exception);
						
					}
					
					
					try {
						// Set new URL
						newRequestNoEncoding.setURL(new HttpUrl (newURLNoEncoding));
						synchronized(specificParametersOfRequests) {
							HashMap<String,String> newParametersOfRequestNotEncoded = new HashMap<String,String>(newParametersOfRequest);
							newParametersOfRequestNotEncoded.put(headerInjectedString, testStringNoEncoding);
							specificParametersOfRequests.put(newRequestNoEncoding,newParametersOfRequest);
						}
						_logger.fine("URL creation of: "+newURLNoEncoding);
						newRequestNoEncoding.addHeader(_headerParameterTested, "GET/"+currentParam+"("+newTokenType+")");
						newRequestNoEncoding.addHeader(headerOriginalRequestId, id.toString());

						// Launch the new created requests
						_model.enqueueRequest(newRequestNoEncoding, currentParam, testStringNoEncoding);
						_logger.fine("URL creation succeeded for: "+newURLNoEncoding);
					} catch (MalformedURLException exception) {
						// Logger level fine as it is normal to have errors during the creation of some invalid URLs
						_logger.fine("Error during the URL creation of: "+exception);
						
					}
				}
			}
		}
		_logger.fine("Done testing GET parameters of Conversation: "+id);
	}
	// 2011-07-08 - JLS - Adding multiple injection tokens - END

	// 2011-03-04 - JLS - Adding support to test only the page name of the request - BEGIN
	private void checkPageFilename(ConversationID id, Request origRequest, Boolean checkForced) {
		_logger.fine("Testing Page Filename of Conversation: "+id);
		// 2011-01-21 - JLS - Adding some comments - BEGIN
		
		// Does the url found has already been tested ?
		String currentUrl = origRequest.getURL().getSHPP();
		String queryString = origRequest.getURL().getQuery();
		if (queryString == null) {
			queryString = "";
		} else {
			queryString = "?"+queryString;
		}
		if (currentUrl.endsWith("/")) {
			_logger.fine("Not treating URL has it does not contain a filename");
			return;
		}
		int secondLast = currentUrl.lastIndexOf("/",currentUrl.length()-1);
		String newBaseUrl = currentUrl.substring(0, secondLast+1);
		
		//if (_model.hasBeenXSSTested(origRequest.getURL(), "PageFilename") && ! checkForced) {
		if (_model.hasBeenXSSTested(newBaseUrl, "PageFilename", "PageFilename") && ! checkForced) {
			_logger.fine("Not testing Url: "+origRequest.getURL()+" with its filename, it has already been tested.");
		} else {
			_logger.fine("Testing PageFilename in URL: "+origRequest.getURL() + " newBaseUrl: "+newBaseUrl);
			requestParameters.put (origRequest.getURL().getSHPP(), "PageFilename/PageFilename");
			
			ArrayList<String> newTokens = generateNewTestTokens();
			
			Iterator<String> iteratorTokens = newTokens.iterator();
			String newToken = null;
			String testString = null;
			Request newRequest = null;
			String newURL = null;
			
			while (iteratorTokens.hasNext()) {
				// Génération d'un paramètre aléatoire unique
				newToken = iteratorTokens.next();

				// Préparation de la requête avec le paramètre modifié				
				// Construction of the URL-encoded request
				testString = Encoding.urlEncode(newToken);
				newRequest = new Request(origRequest);
				newURL = newBaseUrl + testString + queryString;
				// Create the URL objects
				try {
					// Set new URL
					newRequest.setURL(new HttpUrl (newURL));
					
					// Add custom header to know which parameter has been tested
					newRequest.addHeader(_headerParameterTested, "PageFilename/PageFilename");
					
					// Launch the new created requests
					_model.enqueueRequest(newRequest, "PageFilename", testString);
				} catch (MalformedURLException exception) {
					// Logger level fine as it is normal to have errors during the creation of some invalid URLs
					_logger.fine("Error during the URL creation of: "+newURL+" : "+exception);
				}
			}
		}
	}
	// 2011-03-04 - JLS - Adding support to test only the page name of the request - END

	private void checkPostParametersMultipleTable(ConversationID id, Request origRequest, Boolean checkForced) {
		// 2011-06-21 - JLS - TODO: Get out all variable declarations from loops, to clean up a little
		_logger.fine("Testing POST parameters of Conversation: "+id);
		String contentType = origRequest.getHeader("Content-Type");
		if (contentType != null && contentType.indexOf("application/x-www-form-urlencoded") >-1) {
			byte[] requestContent = origRequest.getContent();
			if (requestContent != null && requestContent.length>0) {
				String requestBody = new String(requestContent);
				_logger.info("Request Body: "+requestBody);
				NamedValue[] params = NamedValue.splitNamedValues(requestBody, "&", "=");
				
				ArrayList<String[]> newTokens = null;
				
				for (int i=0; i<params.length; i++) {
					String currentParam = params[i].getName();
					String currentParamValue = params[i].getValue();
					// 2011-03-15 - JLS - Adding a check if URL has already been tested - BEGIN
					if (_model.hasBeenXSSTested(origRequest.getURL().getSHPP(), currentParam, "POST") && ! checkForced) {
						_logger.fine("Not testing Url: "+origRequest.getURL()+"with parameter: "+currentParam+", it has already been tested.");
					} else {
						// 2011-03-15 - JLS - Adding a check if URL has already been tested - END
						_logger.fine("Testing parameter: "+currentParam);
						
						newTokens = generateNewTestTokensTable("");
						// 2011-07-26 - JLS - Adding a button for SQLi tests - BEGIN
						if (_doSQLiTests) {
							newTokens.addAll(generateNewTextSQLiAllTokens(currentParamValue));
							// TODO: Implement a option for evasion
							//newTokens.addAll(generateNewTextSQLiAllTokensWithoutSQLWords(currentParamValue));
							newTokens.addAll(generateNewNumericSQLiAllTokens(currentParamValue));
							// TODO: Implement a option for evasion
							//newTokens.addAll(generateNewNumericSQLiAllTokensWithoutSQLWords(currentParamValue));
						}
						// 2011-07-26 - JLS - Adding a button for SQLi tests - END
						
						String[] newToken = null;
						String newTokenType = null;
						String newTokenValue = null;
						String newTokenIndex = null;
						Iterator<String[]> iteratorTokens = newTokens.iterator();
						while (iteratorTokens.hasNext()) {
							// Engage the test of the current parameter
							
							// Génération d'un paramètre aléatoire unique
							newToken = iteratorTokens.next();
							newTokenType = newToken[0];
							newTokenValue = newToken[1];
							if (newToken.length == 3) {
								newTokenIndex = newToken[2];
							}
							
							
							
							
							// Génération d'un paramètre aléatoire unique
							//String newToken = generateNewTestToken();
							
							
							String testString = Encoding.urlEncode(newTokenValue);
							String testStringNoEncoding = newTokenValue.replaceAll("&","%26").replaceAll("=","%3d");
							
							Request newRequest = new Request(origRequest);
							Request newRequestNoEncoding = new Request(origRequest);
							
							// Préparation de la requête avec le paramètre modifié
							newRequest.setContent(getParametersWithTestString(new String(origRequest.getContent()),currentParam,testString).getBytes());
							newRequestNoEncoding.setContent(getParametersWithTestString(new String(origRequest.getContent()),currentParam,testStringNoEncoding).getBytes());
							
							
							
							// Add custom header to know which parameter has been tested
							HashMap<String,String> newParametersOfRequest = new HashMap<String,String>();
							newParametersOfRequest.put(_headerParameterTested, "POST/"+currentParam+"("+newTokenType+")");
							newParametersOfRequest.put(headerOriginalRequestId, id.toString());
							newParametersOfRequest.put(headerUniqueId,Integer.toString(uniqueId.get()));
							newParametersOfRequest.put(headerTypeOfTest,newTokenType);
							if (newTokenIndex != null) {
								newParametersOfRequest.put(headerTestIndex,newTokenIndex);
							}
							
							synchronized(specificParametersOfRequests) {
								specificParametersOfRequests.put(newRequest,newParametersOfRequest);
								specificParametersOfRequests.put(newRequestNoEncoding,newParametersOfRequest);
							}
							
							newRequest.addHeader(_headerParameterTested, "POST/"+currentParam+"("+newTokenType+")");
							newRequest.addHeader(headerOriginalRequestId, id.toString());
							newRequestNoEncoding.addHeader(_headerParameterTested, "POST/"+currentParam+"("+newTokenType+")");
							newRequestNoEncoding.addHeader(headerOriginalRequestId, id.toString());
							
							
							_model.enqueueRequest(newRequest, currentParam, testString);
							_model.enqueueRequest(newRequestNoEncoding, currentParam, testStringNoEncoding);
							
							// Envoi de la requête modifiée
						}
					// 2011-03-15 - JLS - Adding a check if URL has already been tested - BEGIN
					}
					// 2011-03-15 - JLS - Adding a check if URL has already been tested - END
				}
			} else {
				return;
			}
		}
		if (contentType != null && contentType.indexOf("multipart/form-data") >-1) {
			byte[] requestContent = origRequest.getContent();
			if (requestContent != null && requestContent.length>0) {
				MultiPartContent mpc = new MultiPartContent(contentType, requestContent);
				MultiPartContent mpcNoEncoding = null;
				_logger.info("Testing Multipart POST with "+mpc.size()+" parameters");

				Message message = null;
				Message messageNoEncoding = null;
				
				for (int i=0; i<mpc.size(); i++) {
					mpc = new MultiPartContent(contentType, requestContent);
					mpcNoEncoding = new MultiPartContent(contentType, requestContent);
					message = mpc.get(i);
					messageNoEncoding = mpc.get(i);
					
					String currentParam = mpc.getPartName(i);
					_logger.info("Testing parameter: "+currentParam);
					
					// Génération d'un paramètre aléatoire unique
					String newToken = generateNewTestToken();
					String testString = Encoding.urlEncode(newToken);
					String testStringNoEncoding = newToken;

					Request newRequest = new Request(origRequest);
					Request newRequestNoEncoding = new Request(origRequest);

					// Préparation de la requête avec le paramètre modifié
					message.setContent(testString.getBytes());
					mpc.set(i,message);
					newRequest.setContent(mpc.getBytes());
					
					messageNoEncoding.setContent(testStringNoEncoding.getBytes());
					mpcNoEncoding.set(i,messageNoEncoding);
					newRequestNoEncoding.setContent(mpcNoEncoding.getBytes());

					_model.markAsXSSTested(id,newRequest.getURL(),"POST",currentParam);
					newRequest.addHeader(_headerParameterTested, "POST/"+currentParam);
					newRequestNoEncoding.addHeader(_headerParameterTested, "POST/"+currentParam);
					_model.enqueueRequest(newRequest, currentParam, testString);
					_model.enqueueRequest(newRequestNoEncoding, currentParam, testStringNoEncoding);
					
					// Envoi de la requête modifiée
				}
			} else {
				return;
			}
		}
		if (contentType != null && contentType.indexOf("text/x-gwt-rpc") >-1) {
			byte[] requestContent = origRequest.getContent();
			GWTRPCRequest gwtRequest = new GWTRPCRequest(contentType, requestContent);
			if (requestContent != null && requestContent.length>0) {
				_logger.info("Testing GWT Request with "+gwtRequest.size()+" parameters");
				Vector<String> currentRequestVectorized = gwtRequest.getVector();
				Vector<String> newRequestVectorized = null;
				if (currentRequestVectorized != null) {
					Iterator<String> itr = currentRequestVectorized.iterator();
					int currentObjectIndex = 0;
					Object currentObject = null;
					String currentParam = null;
					while (itr.hasNext()) {
						currentObject = itr.next();
						currentParam = (String) currentObject;
						currentObjectIndex = currentRequestVectorized.indexOf(currentObject);
						_logger.info("Testing parameter: "+currentParam);
						_logger.info("Current position of the parameter: "+currentObject+" is ["+currentObjectIndex+"].");
						// Génération d'un paramètre aléatoire unique
						String newToken = generateNewTestToken();
						String testString = Encoding.urlEncode(newToken);
						String testStringNoEncoding = newToken;
						
						Request newRequest = new Request(origRequest);
						Request newRequestNoEncoding = new Request(origRequest);
						
						// Préparation de la requête avec le paramètre modifié
						currentParam = testString;
						newRequestVectorized = new Vector<String> (currentRequestVectorized);
						newRequestVectorized.setElementAt(currentParam, currentObjectIndex);
						gwtRequest.setVector(newRequestVectorized);
						newRequest.setContent(gwtRequest.getBytes());
						
						currentParam = testStringNoEncoding;
						newRequestVectorized = new Vector <String>(currentRequestVectorized);
						newRequestVectorized.setElementAt(currentParam, currentObjectIndex);
						gwtRequest.setVector(newRequestVectorized);
						newRequestNoEncoding.setContent(gwtRequest.getBytes());
						
						_model.markAsXSSTested(id,newRequest.getURL(),"POST",currentParam);
						newRequest.addHeader(_headerParameterTested, "POST/"+currentParam);
						newRequestNoEncoding.addHeader(_headerParameterTested, "POST/"+currentParam);
						_model.enqueueRequest(newRequest, currentParam, testString);
						_model.enqueueRequest(newRequestNoEncoding, currentParam, testStringNoEncoding);
						
					}
				}
				
			} else {
				return;
			}
		}
		_logger.fine("Done testing POST parameters of Conversation: "+id);
	}	
	
	
	
	public void flush() throws StoreException {
		// 2011-07-29 - JLS - Change behavior if stopping - BEGIN
		// 2011-07-29 - JLS - Adding fetcherQueue sync - BEGIN
		
			_logger.info("Flushing requests.");
			/*if (_model.hasMoreRequests()) {
				Request req = _model.dequeueRequest();
				while (req != null) {
					synchronized(_fetcherQueue) {
						_fetcherQueue.submit(req);
					}
				}
			}
			*/
			/*
			while (! _model.allRequestsAnalyzed()) {
				try {
					Thread.sleep(100);
				} catch (InterruptedException exception) {
					_logger.info("Thread sleep was interrupted");
				}
			}
			*/
			_logger.info("Flushing done.");
		// 2011-07-29 - JLS - Adding fetcherQueue sync - END
		// 2011-07-29 - JLS - Change behavior if stopping - END
	}
	
	public String getPluginName() {
		return "XSS/CRLF ng";
	}
	
	public Object getScriptableObject() {
		return null;
	}
	
	public Hook[] getScriptingHooks() {
		return new Hook[0];
	}
	
	public String getStatus() {
		return _model.getStatus();
	}
	
	public boolean isBusy() {
		return _model.isBusy();
	}
	
	public boolean isModified() {
		return _model.isModified();
	}
	
	public boolean isRunning() {
		return _model.isRunning();
	}
	
	public void run() {
		// To remove ?
		//try {
		Request req;
		_logger.info("Starting XSS-ng");
		_model.setRunning(true);
		
		_model.setStatus("Started");
		_model.setStopping(false);
		// start the fetchers
		_fetcherQueue = new FetcherQueue(getPluginName(), this, _threads, _delay);
		_model.setRunning(true);
		
		while (!_model.isStopping() ||_model.hasMoreRequests()) {
			// 2011-07-29 - JLS - Adding fetcherQueue sync - BEGIN
				req = _model.dequeueRequest();                
				if (req != null) {
					//synchronized(_fetcherQueue) {
						_fetcherQueue.submit(req);
					//}
				}
			
			// 2011-07-29 - JLS - Adding fetcherQueue sync - END
		}
		/*
		if (_model.hasMoreRequests()) {
				Request req = _model.dequeueRequest();
				while (req != null) {
					synchronized(_fetcherQueue) {
						_fetcherQueue.submit(req);
					}
				}
			}
		*/
		_model.setRunning(false);
		_model.setStatus("Stopped");
		//} catch (Exception e) {
		//	_logger.severe("Exception cau;ght: ");
		//	e.printStackTrace();
		//}
	}

	// 2011-01-25 - JLS - Creation of a dedicated log function - BEGIN
	private void setXSSinResponse (Matcher matcher, ConversationID id, Response response, String placeFound, String parameterName, Boolean partial) {
		if (matcher == null || id == null || response == null || placeFound == null || partial == null) {
			return;
		} else {
			if (parameterName == null) {
				parameterName = "";
			}
			if (partial) {
				_logger.info("Response "+id+" matches to PARTIAL XSS in "+placeFound);
			} else {
				_logger.info("Response "+id+" matches to XSS in "+placeFound);
			}
			// 2011-03-14 - JLS - Modification to use the getRequest from conversation instead of the one from the Request - BEGIN
			
			_model.setXSSVulnerable(id, _model.getRequest(id).getURL());
			
			// 2011-05-17 - JLS - Filtering results that are the same - BEGIN
			List<String> matchesAlreadyFound = new ArrayList<String>();
			String matchFiltered = null;
			//String tempString = null;
			Boolean foundNextOne = true;
			
			String parameterTested = _model.getRequest(id).getHeader(_headerParameterTested);
			StringBuffer listOfMatches = new StringBuffer(); // placeFound+":"+partial+":"+parameterName+":"+matchFiltered);
			
			while (foundNextOne) {
				matchFiltered = matcher.group();
				// 2011-12-13 - JLS - Do not filter results - BEGIN
				/*
				matchFiltered = matchFiltered.replaceAll("%[0-9a-fA-F]{2}", "");
				matchFiltered = matchFiltered.replaceAll("\\\\[xX][0-9a-fA-F]{2}", "");
				matchFiltered = matchFiltered.replaceAll("\\\\[xX][0-9a-fA-F]{4}", "");
				matchFiltered = matchFiltered.replaceAll("&[a-z&&[^;]]+;#[0-9]{2}", "");
				matchFiltered = matchFiltered.replaceAll("&[a-z&&[^;]]+;", "");
				*/
				// 2011-12-13 - JLS - Do not filter results - END
				if (! matchesAlreadyFound.contains(matchFiltered)) {
					matchesAlreadyFound.add(matchFiltered);
					listOfMatches.append (injectedParameterSeparator+placeFound+":"+ (partial ? "Partial" : "Full") +":"+parameterName+":"+matchFiltered);
				}
				foundNextOne = matcher.find();
				// 2011-05-17 - JLS - Filtering results that are the same - END
			}

			if (parameterTested != null) {
				_model.setXSSVulnerableParameter(id, _model.getRequest(id).getURL(), parameterTested, listOfMatches.toString());
			}
		}
	}
	// 2011-01-25 - JLS - Creation of a dedicated log function - END		

	private void setXSSinResponse (String information, ConversationID id, Response response, String placeFound, String parameterName, Boolean partial) {
		if (information == null || id == null || placeFound == null || partial == null) {
			_logger.info("Null parameters, leaving.");
			return;
		} else {
			if (parameterName == null) {
				parameterName = "";
			}
			if (partial) {
				_logger.info("Response "+id+" matches to PARTIAL XSS in "+placeFound);
			} else {
				_logger.info("Response "+id+" matches to XSS in "+placeFound);
			}
			HttpUrl requestUrl = _model.getRequest(id).getURL();
			_model.setXSSVulnerable(id, requestUrl);
			_model.setXSSVulnerableParameter(id, requestUrl, parameterName, injectedParameterSeparator+placeFound+":"+(partial ? "Partial" : "Full")+":"+parameterName+":"+information);
		}
	}
	
	public void responseReceived(Response response) {
		responseReceivedWithReanalyse(response, false);
	}



	
	// 2011-07-13 - JLS - Better XSS detection - BEGIN

	private String removeDuplicates(String s) {
		StringBuilder noDupes = new StringBuilder();
		for (int i = 0; i < s.length(); i++) {
			String si = s.substring(i, i + 1);
			if (noDupes.indexOf(si) == -1) {
				noDupes.append(si);
			}
		}
		return noDupes.toString();
	}
	
	
	// Remove &lt, etc from a String
	public String removeEntities(String stringToClean) {
		String[] htmlChars = {"&#[0-1][0-9]{2};","&sp","&excl","&quot","&num","&dollar","&percnt","&apos","&lpar","&rpar","&ast","&hyphen","&period","&sol","&colon","&semi","&lt","&equals","&gt","&quest","&commat","&lsqb","&bsol","&rsqb","&lowbar","&grave","&lcub","&verbar","&rcub","&tilde","&nbsp","&iexcl","&curren","&cent","&pound","&yen","&brvbar","&sect","&uml","&copy","&ordf","&laquo","&not","&shy","&reg","&macr","&deg","&plusmn","&sup2","&sup3","&acute","&micro","&para","&middot","&cedil","&sup1","&ordm","&raquo","&frac14","&frac12","&frac34","&iquest","&Agrave","&Aacute","&Acirc","&Atilde","&Auml","&Aring","&AElig","&Ccedil","&Egrave","&Eacute","&Ecirc","&Euml","&Igrave","&Iacute","&Icirc","&Iuml","&ETH","&Ntilde","&Ograve","&Oacute","&Ocirc","&Otilde","&Ouml","&times","&Oslash","&Ugrave","&Uacute","&Ucirc","&Uuml","&Yacute","&THORN","&szlig","&agrave","&aacute","&acirc","&atilde","&auml","&aring","&aelig","&ccedil","&egrave","&eacute","&ecirc","&euml","&igrave","&iacute","&icirc","&iuml","&eth","&ntilde","&ograve","&oacute","&ocirc","&otilde","&ouml","&divide","&oslash","&ugrave","&uacute","&ucirc","&uuml","&yacute","&thorn","&yuml","&OElig","&oelig","&Scaron","&scaron","&Yuml","&circ","&ensp","&emsp","&thinsp","&ndash","&mdash","&lsquo","&rsquo","&sbquo","&ldquo","&rdquo","&bdquo","&dagger","&Dagger","&hellip","&permil","&lsaquo","&rsaquo","&euro","&trade","&plus","&comma","&amp"};
		String stringCleaned = stringToClean;
		for (int i=0; i<htmlChars.length; i++) {
			// 2013-07-04 - JLS - Remove htmlentities even if upper - BEGIN
			String htmlCharsString = new String(htmlChars[i]+";?");
			stringCleaned = stringCleaned.replaceAll(htmlCharsString,"");
			stringCleaned = stringCleaned.replaceAll(htmlCharsString.toUpperCase(),"");
			// 2013-07-04 - JLS - Remove htmlentities even if upper - END
		}
		stringCleaned = stringCleaned.replaceAll("%[0-9A-F]{2}", "");
		return stringCleaned;
	}
	
	// Remove specific patterns from injectedString
	public String getCharsInjected(String stringToAnalyze) {
		return (removeDuplicates(stringToAnalyze.replaceAll("(?is)("+patternPrefix+"[0-9]+|"+patternSuffix+"|"+patternHtmlTag+")","")));
	}
	
	// 2011-12-13 - JLS - TODO: add support of end character in string to check if it can escape or not, might be wiser in some cases
	// Checks if the first Character of the String is also present in the injectedString found
	public boolean checkPossibleEscape(String injectionFound, char firstDelimiter) {
		//char firstDelimiter = injectionFound.charAt(0);
		if (injectionFound.substring(1).indexOf(firstDelimiter)>=0) {
			_logger.finer("Injection with ESCAPE possible: try "+injectionFound.substring(1,5)+firstDelimiter);
			return true;
		} else {
			_logger.finer("No ESCAPE possible.");
			String cleanedString = removeEntities(injectionFound);
			_logger.finer("Cleaned String: "+cleanedString);
			_logger.finer("Chars injected: "+getCharsInjected(cleanedString));
			return false;
		}
	}

	// 2011-07-13 - JLS - Better XSS detection - END

	// 2011-11-22 - JLS - Adding support to remove some text from the analysis - BEGIN
	// 2011-11-22 - JLS - TODO: finish implementation of this
	public int diffResponsesTODO(Response originalResponse, Response newResponse) {
		return(0);
	}	
	// 2011-11-22 - JLS - Adding support to remove some text from the analysis - END

	
	public int diffResponses(Response originalResponse, Response newResponse) {
		if (originalResponse == null || newResponse == null) {
			_logger.warning("ERROR: null parameters, leaving.");
			return -1;
		}
		diff_match_patch dmp = new diff_match_patch();
		//_logger.finer("Computing differences between: "+originalResponse.getConversationID () + " and " + newResponse.getConversationID ());
		Response resp_orig = new Response(originalResponse);
		resp_orig.deleteHeader("Date");
		resp_orig.deleteHeader("Set-Cookie");
		
		Response resp_new = new Response(newResponse);
		resp_new.deleteHeader("Date");
		resp_new.deleteHeader("Set-Cookie");
		
		LinkedList<name.fraser.neil.plaintext.diff_match_patch.Diff> diffs = dmp.diff_main(resp_orig.toString().replaceFirst("(?i)Content-length:[ ]+[0-9]+\r\n","\r\n"), resp_new.toString().replaceFirst("(?i)Content-length:[ ]+[0-9]+\r\n","\r\n"), false);
		dmp.diff_cleanupSemantic(diffs);
		// Loop initialization
		Iterator<Diff> listIterator = diffs.iterator();
		Diff currentDiff = null;
		Diff previousDiff = null;
		while (listIterator.hasNext()) {
			previousDiff = currentDiff;
			currentDiff = listIterator.next();
			if (currentDiff != null) {
				switch (currentDiff.operation) {
				case INSERT:
					_logger.finest("INSERT: " + currentDiff.text);
					if (previousDiff != null && previousDiff.operation == diff_match_patch.Operation.EQUAL) {
						_logger.finest("In NEW conversation only: " + currentDiff.text);
					} else if (previousDiff != null && previousDiff.operation == diff_match_patch.Operation.DELETE) {
						String displayCurrentDiff = currentDiff.text;
						if (displayCurrentDiff.length() > 40) {
							displayCurrentDiff = displayCurrentDiff.substring(0,40) + "...8<---";
						}
						String displayPreviousDiff = previousDiff.text;
						if (displayPreviousDiff.length() > 40) {
							displayPreviousDiff = displayPreviousDiff.substring(0,40) + "...8<---";
						}
						_logger.finest("Text: \"" + displayCurrentDiff.replaceAll("[\t]+","\\\\t").replaceAll("[\n]+","\\\\n") + "\" replaced ==> \"" + displayPreviousDiff.replaceAll("[\t]+","\\\\t").replaceAll("[\n]+","\\\\n") + "\"");
					} else {
						_logger.finest("SHOULD HAPPEN ??? INSERT: In NEW conversation: " + currentDiff.text);
					}
					break;
				case DELETE:
					_logger.finest("DELETE: " + currentDiff.text);
					// Do nothing, handled by others cases
					break;
				case EQUAL:
					_logger.finest("EQUAL");
					if (previousDiff != null && previousDiff.operation == diff_match_patch.Operation.DELETE) {
						_logger.finest("In OLD conversation only: " + previousDiff.text);
					} else if (previousDiff != null && previousDiff.operation == diff_match_patch.Operation.DELETE) {
						_logger.finest("DELETE AGAIN: \"" + currentDiff.text + "\" and BEFORE: \"" + previousDiff.text + "\"");
					} else if (previousDiff != null) {
						// Do nothing, just same text
					}
					break;
				}
			}
		}
		int levenshtein = dmp.diff_levenshtein(diffs);
		_logger.finer("Levensthein: "+ levenshtein);
		// Test with content length correlation
		int lengthFactor = java.lang.Math.abs(newResponse.getContent().length - originalResponse.getContent().length);
		_logger.finer("lengthFactor is: "+ lengthFactor);
		if (lengthFactor < 10) {
			levenshtein = Math.round(levenshtein /2);
			_logger.finer("levenshtein is now: "+ levenshtein);
		}
		//int correlatedLevenshtein = levenshtein * (
		return(levenshtein);
	}	
	
	
	private HashMap<String,String> getSpecificParametersOfRequest(Request request) {
		//String parameterTested = request.getHeader(_headerParameterTested);
		
		// HashMap containing the specificParameters of the request (type of test, parameter tested, etc).
		HashMap<String,String> specificParameters = null;
		
		//String typeOfTest = null;
		synchronized(specificParametersOfRequests) {
			specificParameters = specificParametersOfRequests.get(request);
		}
		
		// General HashMap does not contain the parameter tested etc. Either it's an error or the current WebScarab instance is not the one used to generate the tests
		// In this case, try to load the parameters from the headers
		if (specificParameters == null) {
			
			String testedParameterFromHeader = request.getHeader(_headerParameterTested);
			String originalRequestIdFromHeader = request.getHeader(headerOriginalRequestId);
			// Check if needed headers are present and not empty
			if (testedParameterFromHeader != null && ! testedParameterFromHeader.isEmpty() 
				&& originalRequestIdFromHeader != null && ! originalRequestIdFromHeader.isEmpty())
			{
				// A new HashMap can be created as values are present
				specificParameters = new HashMap<String,String>();
				specificParameters.put(_headerParameterTested, testedParameterFromHeader);
				specificParameters.put(headerOriginalRequestId, originalRequestIdFromHeader);
				
				// Split the header value based on regexp
				
				
				// SQLi regex matches
				Pattern patternSplittingHeaderForSQLi = Pattern.compile("^[^/]+/([^(]+)\\((SQLi-.+)-([0-9]+)\\)$");
				Matcher matcherSplittingHeaderForSQLi = patternSplittingHeaderForSQLi.matcher(testedParameterFromHeader);
				if (matcherSplittingHeaderForSQLi.find()) {
					specificParameters.put(headerTypeOfTest, matcherSplittingHeaderForSQLi.group(2) + "-" + matcherSplittingHeaderForSQLi.group(3));
					specificParameters.put(headerTestIndex,matcherSplittingHeaderForSQLi.group(3));
				}
				
				// XSS or other test regex matches
				Pattern patternSplittingHeaderForOtherTests = Pattern.compile("^[^/]+/([^(]+)\\(([^0-9]+)\\)$");
				Matcher matcherSplittingHeaderForOtherTests = patternSplittingHeaderForOtherTests.matcher(testedParameterFromHeader);
				if (matcherSplittingHeaderForOtherTests.find()) {
					specificParameters.put(headerTypeOfTest, matcherSplittingHeaderForOtherTests.group(2));
					//specificParameters.put(headerTestIndex,0);
				}
			}
		}
		return(specificParameters);
	}
	
	public void checkForSQLiInResponse(Response response, Boolean reAnalyse, Boolean fromPlugin) {
		/*
		Tests Wavsep qui ne passent pas: 
		http://192.168.200.200:80/wavsep/SInjection-Detection-Evaluation-GET-200Valid/Case5-InjectionInSearchOrderBy-String-BinaryDeliberateRuntimeError-WithDifferent200Responses.jsp?orderby=msgid
		
		
		*/
		if (response == null || reAnalyse == null || fromPlugin == null) {
			_logger.severe("Invalid parameters: response, reAnalyse or fromPlugin is NULL. Leaving");
			return;
		}
		_logger.finer("checkForSQLiInResponse: reAnalyse: " + reAnalyse + " fromPlugin: " + fromPlugin);
		
		// 2011-01-25 - JLS - Modifying the search to include the headers - BEGIN 
		//NamedValue [] headers = response.getHeaders();
		// 2011-01-25 - JLS - Modifying the search to include the headers - END
		// 2011-01-13 - JLS - Adding correct pattern matching - BEGIN

		ConversationID id = null;
		Request request = null;
		String parameterTested = null;
		
		// Representation of the parameter tested without the index number to avoid duplicates
		String parameterTestedToLog = null;

		// 2011-03-14 - JLS - Adding a new analyse support - BEGIN
		request = response.getRequest();
		if (request == null) {
			//id = response.getConversationID ();
			//request = _model.getRequest(id);
			//if (request == null) {
				_logger.severe ("No request associated with response received. Aborting analysis");
				return;
			//}
		}
		// Only get the tested parameter if request from the plugin
		if (fromPlugin) {
			// 2011-12-13 - JLS - Calling getSpecificParametersOfRequest to simplify - BEGIN
			HashMap<String,String> specificParameters = getSpecificParametersOfRequest(request);
			String typeOfTest = null;
			/*
			
			// 2011-07-15 - JLS - TODO: modify to get the parameter from the HashMap once all check Methods modified
			parameterTested = request.getHeader(_headerParameterTested);
			
			// HashMap containing the specificParameters of the request (type of test, parameter tested, etc).
			HashMap<String,String> specificParameters = null;
			
			String typeOfTest = null;
			synchronized(specificParametersOfRequests) {
				specificParameters = specificParametersOfRequests.get(request);
			}
			// 2011-12-09 - JLS - Adding header support in case of an analysis in another session (where the HashMap is not filled) - BEGIN
			// General HashMap does not contain the parameter tested etc. Either it's an error or the current WebScarab instance is not the one used to generate the tests
			
			// In this case, try to load the parameters from the headers
			if (specificParameters == null) {
				
				String testedParameterFromHeader = request.getHeader(_headerParameterTested);
				String originalRequestIdFromHeader = request.getHeader(headerOriginalRequestId);
				// Check if needed headers are present and not empty
				if (testedParameterFromHeader != null && ! testedParameterFromHeader.isEmpty() 
					&& originalRequestIdFromHeader != null && ! originalRequestIdFromHeader.isEmpty())
				{
					// A new HashMap can be created as values are present
					specificParameters = new HashMap<String,String>();
					specificParameters.put(_headerParameterTested, testedParameterFromHeader);
					specificParameters.put(headerOriginalRequestId, originalRequestIdFromHeader);
					
					// Split the header value based on regexp
					Pattern patternSplittingHeader = Pattern.compile("^[^/]+/([^(]+)\\((SQLi-.+)-([0-9]+)\\)$");
					Matcher matcherSplittingHeader = patternSplittingHeader.matcher(testedParameterFromHeader);
					if (matcherSplittingHeader.find()) {
						specificParameters.put(headerTypeOfTest, matcherSplittingHeader.group(2) + "-" + matcherSplittingHeader.group(3));
						specificParameters.put(headerTestIndex,matcherSplittingHeader.group(3));
					}
				}
			}
			*/
			// 2011-12-13 - JLS - Calling getSpecificParametersOfRequest to simplify - END
			
			if (specificParameters != null) {
				Pattern patternSplittingToLog = Pattern.compile("^(.+\\(SQLi-[^-]+-[0-9]+)-[0-9]+\\)$");
				Matcher matcherSplittingToLog = patternSplittingToLog.matcher(specificParameters.get(_headerParameterTested));
				if (matcherSplittingToLog.find()) {
					parameterTestedToLog = matcherSplittingToLog.group(1) + ")";
				} else {
					// Should not happen
					parameterTestedToLog = parameterTested;
				}
			
				_logger.finer("parameterTested from header : "+parameterTested);
				_logger.finer("parameterTested from HashMap: "+specificParameters.get(_headerParameterTested));
				parameterTested = specificParameters.get(_headerParameterTested);
				
				typeOfTest = specificParameters.get(headerTypeOfTest);
				String testId = null;
				if (typeOfTest != null && typeOfTest.startsWith("SQLi-")) {
					Pattern patternSQLiTest = Pattern.compile("^(SQLi-Text|SQLi-Text2|SQLi-Num|SQLi-Num2)-([0-9]+).*");
					Matcher matcherSQLiTest = patternSQLiTest.matcher(typeOfTest);
					if (matcherSQLiTest.find()) {
						typeOfTest = matcherSQLiTest.group(1);
						_logger.finer("typeOfTest is: " + typeOfTest);
						testId = matcherSQLiTest.group(2);
						_logger.finer("testId is: " + testId);
					} else {
						_logger.severe("Wrong SQLi pattern found, leaving.");
						return;
					}
					
					// UniqueId of the SQLi Test tried
					//String testId =  specificParameters.get(headerUniqueId);
					
					
					
					Response[] emptyTable = {null,null,null,null,null,null,null,null, null};
					Response[] tableOfResponses = null;
					Boolean wasEmpty = Boolean.TRUE;
					// 2011-12-28 - JLS - Adding a test if the requests have already been analyzed - BEGIN
					Boolean wasFull = Boolean.FALSE;
					// 2011-12-28 - JLS - Adding a test if the requests have already been analyzed - END
					synchronized(testedParametersForSQLiAll) {
						Map<String,Response[]> hashMapOfCurrentResponses = testedParametersForSQLiAll.get(typeOfTest);
						synchronized(hashMapOfCurrentResponses) {
							// If there is no table associated yet
							if (!hashMapOfCurrentResponses.containsKey(testId)) {
								tableOfResponses = new Response[emptyTable.length];
								System.arraycopy(emptyTable, 0, tableOfResponses, 0, emptyTable.length);
							} else {
								tableOfResponses = hashMapOfCurrentResponses.get(testId);
								wasEmpty = Boolean.FALSE;
								// 2011-12-28 - JLS - Adding a test if the requests have already been analyzed - BEGIN
								Boolean fullArray = Boolean.TRUE;
								for (int i=0; i<tableOfResponses.length; i++) {
									if (tableOfResponses[i] == null) {
										fullArray = Boolean.FALSE;
									}
								}
								if (fullArray.equals(Boolean.TRUE)) {
									wasFull = Boolean.TRUE;
								}
								// 2011-12-28 - JLS - Adding a test if the requests have already been analyzed - END
							}
							// Get the test index (0 to 7)
							int indexOfRequest = Integer.parseInt(specificParameters.get(headerTestIndex));
							// Add the current request to the array
							// TODO: TO MODIFY
							_logger.finer("indexOfRequest: "+indexOfRequest);
							tableOfResponses[indexOfRequest] = response;
							// Reinsert the array
							hashMapOfCurrentResponses.put(testId,tableOfResponses);
						}
					}
					if (! wasEmpty && ! wasFull) {
						Boolean fullArray = Boolean.TRUE;
						for (int i=0; i<tableOfResponses.length; i++) {
							if (tableOfResponses[i] == null) {
								fullArray = Boolean.FALSE;
							}
						}
						if (fullArray) {
							// Do the analysis, all responses are back
							int[] diffs = {0,0,0,0,0,0,0,0,0,0,0,0};
							diffs[0] = diffResponses(tableOfResponses[0],tableOfResponses[1]);
							_logger.fine("Diff (1) and (2) is: "+diffs[0]);
							
							diffs[1] = diffResponses(tableOfResponses[2],tableOfResponses[3]);
							_logger.fine("Diff (3) and (4) is: "+diffs[1]);
							
							diffs[2] = diffResponses(tableOfResponses[0],tableOfResponses[2]);
							_logger.fine("Diff (1) and (3) is: "+diffs[2]);
							
							diffs[3] = diffResponses(tableOfResponses[1],tableOfResponses[3]);
							_logger.fine("Diff (2) and (4) is: "+diffs[3]);
							
							diffs[4] = diffResponses(tableOfResponses[0],tableOfResponses[3]);
							_logger.fine("Diff (1) and (4) is: "+diffs[4]);
							
							diffs[5] = diffResponses(tableOfResponses[0],tableOfResponses[4]);
							_logger.fine("Diff (1) and (5) is: "+diffs[5]);
							
							ConversationID originalRequestId = new ConversationID(Integer.valueOf(specificParameters.get(headerOriginalRequestId)));
							// 2011-11-22 - JLS - Use of id of conversation after - BEGIN
							// 2011-12-29 - JLS - Deactivate this behavior and use originalRequestId instead - BEGIN
							//id = originalRequestId;
							// 2011-12-29 - JLS - Deactivate this behavior and use originalRequestId instead - END
							// 2011-11-22 - JLS - Use of id of conversation after - END
							diffs[6] = diffResponses(_model.getResponse(originalRequestId),tableOfResponses[5]);
							_logger.fine("Diff (0) and (6) is: "+diffs[6]);
							
							diffs[7] = diffResponses(_model.getResponse(originalRequestId),tableOfResponses[6]);
							_logger.fine("Diff (0) and (7) is: "+diffs[7]);
							
							diffs[8] = diffResponses(_model.getResponse(originalRequestId),tableOfResponses[7]);
							_logger.fine("Diff (0) and (8) is: "+diffs[8]);
							
							diffs[9] = diffResponses(tableOfResponses[5],tableOfResponses[6]);
							_logger.fine("Diff (6) and (7) is: "+diffs[9]);
							
							diffs[10] = diffResponses(tableOfResponses[6],tableOfResponses[7]);
							_logger.fine("Diff (7) and (8) is: "+diffs[10]);
							
							// 2013-10-08 - JLS - Adding SQLi difference to avoid false-positive - BEGIN
							diffs[11] = diffResponses(_model.getResponse(originalRequestId),tableOfResponses[8]);
							_logger.fine("Diff (0) and (9) is: "+diffs[11]);
							// 2013-10-08 - JLS - Adding SQLi difference to avoid false-positive - END
							
							if (diffResponses(tableOfResponses[4],tableOfResponses[5]) < 15 && diffResponses(tableOfResponses[4],tableOfResponses[6]) < 15 && diffResponses(tableOfResponses[4],tableOfResponses[7]) < 15) {
								if (diffResponses(tableOfResponses[0],tableOfResponses[4]) < 15 && diffResponses(tableOfResponses[1],tableOfResponses[5]) < 15) {  
									//validSQLordersStability = Boolean.TRUE;
								}
							}
							
							Boolean errorStability = Boolean.FALSE;
							Boolean quoteStability = Boolean.FALSE;
							Boolean lowRisk = Boolean.FALSE;
							Boolean notErrorBased = Boolean.FALSE;
							
							int numberOfConfirmationHits = 0;
							
							if (diffs[0] < 15) {
								_logger.fine("Parameter: "+parameterTested +" Requetes (1) et (2): Score levenshtein < 15 entre elles");
								errorStability = Boolean.TRUE;
							}
							if (diffs[1] < 15) {
								_logger.fine("Parameter: "+parameterTested +" Requetes (3) et (4): Score levenshtein < 15 entre elles");
								quoteStability = Boolean.TRUE;
							}
							
							// Cas flagrant de SQLi
							if (diffs[2] > 20 || diffs[3] > 20 || diffs[4] > 20) {
								numberOfConfirmationHits++;
								if (diffs[2] > 20) {
									_logger.fine("Parameter: "+parameterTested +" Requetes (1) et (3): Risque de SQLi");
									//numberOfConfirmationHits++;
								}
								if (diffs[3] > 20) {
									_logger.fine("Parameter: "+parameterTested +" Requetes (2) et (4): Risque de SQLi");
									//numberOfConfirmationHits++;
								}
								if (diffs[4] > 20) {
									_logger.fine("Parameter: "+parameterTested +" Requetes (1) et (4): Risque de SQLi");
									//numberOfConfirmationHits++;
								}
							}
							// Cas où la SQLi n'est pas basée sur des codes d'erreur ou n'existe pas
							//if (diffs[4] < 20) {
							else {
								_logger.fine("Parameter: "+parameterTested +" Requetes (1) et (4): PEU de risque de SQLi ou non basé sur l'erreur (low risk).");
								lowRisk = Boolean.TRUE;
								notErrorBased = Boolean.TRUE;
							}
							
							// Pas pertinent dans le cas d'une SQLi-Num car même type de requête
							if (typeOfTest.equals("SQLi-Text") || typeOfTest.equals("SQLi-Text2")) {
								if (diffs[5] < 10) {
									if (lowRisk.equals(Boolean.FALSE)) {
										_logger.fine("Parameter: "+parameterTested +" Requetes (1) et (5): score faible => confirme SQLi");
										numberOfConfirmationHits++;
									}
								} else {
									_logger.fine("Parameter: "+parameterTested +" Requetes (1) et (5): score HAUT => low risk");
									lowRisk = Boolean.TRUE;
									notErrorBased = Boolean.TRUE;
								}
							}
							
							if (diffs[6] < 20 && notErrorBased.equals(Boolean.FALSE)) {
								_logger.fine("Parameter: "+parameterTested +" Requetes (0) et (6): score faible => confirme SQLi");
								numberOfConfirmationHits++;
								if (lowRisk) {
									lowRisk = Boolean.FALSE;
									notErrorBased = Boolean.TRUE;
									_logger.fine("Unsetting lowRisk");
								}
							} else {
								_logger.fine("Parameter: "+parameterTested +" Requetes (0) et (6): score HAUT => invalide la SQLi");
								// 2011-12-28 - JLS - Don't push down the value if already marked as low risk
								if (!lowRisk) {
									numberOfConfirmationHits = numberOfConfirmationHits -2;
								}
							}
							
							
							// 2013-10-08 - JLS - Adding SQLi difference to avoid false-positive - BEGIN
							if (diffs[11] < 20 && notErrorBased.equals(Boolean.FALSE)) {
								_logger.fine("Parameter: "+parameterTested +" Requetes (0) et (9): score faible => confirme SQLi");
								numberOfConfirmationHits++;
								if (lowRisk) {
									lowRisk = Boolean.FALSE;
									notErrorBased = Boolean.TRUE;
									_logger.fine("Unsetting lowRisk");
								}
							} else {
								_logger.fine("Parameter: "+parameterTested +" Requetes (0) et (9): score HAUT => invalide la SQLi");
								// 2011-12-28 - JLS - Don't push down the value if already marked as low risk
								if (!lowRisk) {
									numberOfConfirmationHits = numberOfConfirmationHits -2;
								}
							}
							// 2013-10-08 - JLS - Adding SQLi difference to avoid false-positive - END
							
							if (diffs[7] > 20) {
								_logger.fine("Parameter: "+parameterTested +" Requetes (0) et (7): score haut => confirme SQLi");
								numberOfConfirmationHits++;
							} /*else {
								_logger.fine("Parameter: "+parameterTested +" Requetes (0) et (7): score HAUT => invalide la SQLi");
								numberOfConfirmationHits = numberOfConfirmationHits -2;
							}
							*/
							// 2011-12-28 - JLS - Tweaking SQLi search in case of SQLi Num and no error when invalid request - BEGIN
							// In case of a SQLi Num where the behavior is: default value when wrong OR list of values if the SQL request is VALID
							if (notErrorBased.equals(Boolean.TRUE) && diffs[7] > 20 && (typeOfTest.equals("SQLi-Num") || typeOfTest.equals("SQLi-Num2"))) {
								_logger.fine("Parameter: "+parameterTested +" Requetes (0) et (7): score HAUT => suspicion SQLi Num!");
								numberOfConfirmationHits++;
								// If diff with (8) is also big, no more a low risk
								if (diffs[8] > 30) {
									lowRisk = Boolean.FALSE;
									_logger.fine("Unsetting lowRisk");
								}
							}
							// No error message when invalid request but different result when "OR FALSE" and "OR TRUE OR FALSE"
							if (notErrorBased.equals(Boolean.TRUE)) {
								if (diffs[9] > 20 && diffs[10] > 20) {
									numberOfConfirmationHits++;
									lowRisk = Boolean.FALSE;
									if (diffs[9] > 20) {
										_logger.fine("Parameter: "+parameterTested +" Requetes (6) et (7): score HAUT => suspicion SQLi.");
									}
									if (diffs[10] > 20) {
										_logger.fine("Parameter: "+parameterTested +" Requetes (7) et (8): score HAUT => suspicion SQLi.");
									}
								} else {
									numberOfConfirmationHits = numberOfConfirmationHits -2;
									lowRisk = Boolean.TRUE;
									_logger.fine("Setting lowRisk");
								}
							}
							// 2011-12-28 - JLS - Tweaking SQLi search in case of SQLi Num and no error when invalid request - END

							if (diffs[8] > 30) {
								_logger.fine("Parameter: "+parameterTested +" Requetes (0) et (8): score Haut => CONFIRMATION SQLi");
								numberOfConfirmationHits++;
							} else {
								_logger.fine("Parameter: "+parameterTested +" Requetes (0) et (8): score faible => invalide la SQLi");
								numberOfConfirmationHits = numberOfConfirmationHits -2;
							}								
							if (errorStability && quoteStability) {
								
								//if ((lowRisk || numberOfConfirmationHits <=0) && ! (diffs[2] > 10 && diffs[3] > 10 && diffs[4] < 10 && diffs[5] < 10)) {
								if ((lowRisk && numberOfConfirmationHits <=2) || numberOfConfirmationHits <=0) {
									_logger.fine("Parameter: "+parameterTestedToLog +" No "+typeOfTest+" found.");
								} else {
									_logger.severe("Parameter: "+parameterTestedToLog +" SQLi found in conversation " + originalRequestId + " !");
									_logger.severe("Parameter: "+parameterTestedToLog +" stability is OK.");
									_logger.severe("Parameter: "+parameterTestedToLog +" lowRisk is: " + lowRisk);
									_logger.severe("Parameter: "+parameterTestedToLog +" notErrorBased is: " + notErrorBased);
									_logger.severe("Parameter: "+parameterTestedToLog +" confidence value is: "+numberOfConfirmationHits+ " on (0->4).");
									_logger.severe("Diff matrix for " + parameterTestedToLog + " is: " + Arrays.toString(diffs));
									_logger.severe("Diff (1) and (2) is: "+diffs[0]);
									_logger.severe("Diff (3) and (4) is: "+diffs[1]);
									_logger.severe("Diff (1) and (3) is: "+diffs[2]);
									_logger.severe("Diff (2) and (4) is: "+diffs[3]);
									_logger.severe("Diff (1) and (4) is: "+diffs[4]);
									_logger.severe("Diff (1) and (5) is: "+diffs[5]);
									_logger.severe("Diff (0) and (6) is: "+diffs[6]);
									_logger.severe("Diff (0) and (7) is: "+diffs[7]);
									_logger.severe("Diff (0) and (8) is: "+diffs[8]);
									_logger.severe("Diff (6) and (7) is: "+diffs[9]);
									_logger.severe("Diff (7) and (8) is: "+diffs[10]);
									_logger.severe("Diff (0) and (9) is: "+diffs[11]);
							
									setXSSinResponse("SQLi found! Confidence: "+numberOfConfirmationHits, originalRequestId, response, "body", parameterTestedToLog, false);
								}
							}
						}
					}
				}
			}
		}
		_logger.finer("checkForSQLiInResponse: finished analyse.");
	}
	
	
	
	public void checkForXSSInResponse(Response response, final ConversationID id, Boolean reAnalyse, Boolean fromPlugin) {
		// 2011-06-20 - JLS - TODO: Add an analysis of the status of the response and a regexp check to verify if the response is correct compared to the original response
		
		// 2011-03-14 - JLS - Verifying parameters - BEGIN
		if (response == null || reAnalyse == null || fromPlugin == null) {
			_logger.severe("Invalid parameters: response, reAnalyse or fromPlugin is NULL. Leaving");
			return;
		}
		// 2011-03-14 - JLS - Verifying parameters - END
		
		// 2011-12-13 - JLS - Checking content-type - BEGIN
		if (! checkContentTypeOK(response.getHeader("Content-Type"))) {
			_logger.fine("Conversation does not contain an usable Content-Type, not treated.");
			return;
		}
		// 2011-12-13 - JLS - Checking content-type - END
		
		// 2011-03-15 - JLS - Adding a flag to know if a XSS vulnerability has been found or not - BEGIN
		Boolean xssFound = false;
		// 2011-03-15 - JLS - Adding a flag to know if a XSS vulnerability has been found or not - BEGIN
		// 2011-01-25 - JLS - Modifying the search to include the headers - BEGIN 
		NamedValue [] headers = response.getHeaders();
		String body = new String(response.getContent());
		// 2011-01-25 - JLS - Modifying the search to include the headers - END
		// 2011-01-13 - JLS - Adding correct pattern matching - BEGIN

		//ConversationID id = null;
		Request request = null;
		String parameterTested = null;

		// 2011-12-13 - JLS - Calling getSpecificParametersOfRequest to simplify - BEGIN
		HashMap<String,String> specificParameters = null;
		// 2011-12-13 - JLS - Calling getSpecificParametersOfRequest to simplify - END
		
		// 2011-12-09 - JLS - Adding a check if response has a Request associated - BEGIN
		request = response.getRequest();
		if (request == null) {
			_logger.severe ("No request associated with response received. Aborting analysis");
			return;
		}
		// 2011-12-09 - JLS - Adding a check if response has a Request associated - END

		//id = response.getConversationID();
			

		// Only get the tested parameter if request from the plugin
		if (fromPlugin) {
			_logger.fine("Request is from plugin");
			
			// 2011-12-13 - JLS - Calling getSpecificParametersOfRequest to simplify - BEGIN
			specificParameters = getSpecificParametersOfRequest(request);
			if (null == specificParameters) {
				_logger.info("Could not get parameters from conversation " + id + ", so not analyzing it.");
				return;
			}
			parameterTested = specificParameters.get(_headerParameterTested);
			
			/*
			
			// 2011-07-15 - JLS - TODO: modify to get the parameter from the HashMap once all check Methods modified
			parameterTested = request.getHeader(_headerParameterTested);
			HashMap<String,String> specificParameters = null;
			synchronized(specificParametersOfRequests) {
				specificParameters = specificParametersOfRequests.get(request);
			}
			
			if (specificParameters != null) {
				_logger.fine("parameterTested from header : "+parameterTested);
				_logger.fine("parameterTested from HashMap: "+specificParameters.get(_headerParameterTested));
				parameterTested = specificParameters.get(_headerParameterTested);
			}
			*/
			// 2011-12-13 - JLS - Calling getSpecificParametersOfRequest to simplify - END
			
			if (parameterTested != null) {
				// 2011-12-09 - JLS - Cleanup!!! Remove adding conversation to the framework as it's not to be done here - BEGIN
				//id = response.getConversationID();
				// 2011-12-09 - JLS - Cleanup!!! Remove adding conversation to the framework as it's not to be done here - END
				
				// 2011-07-07 - JLS - TODO: implement correct mark of the request sent
				if ("PageFilename".equalsIgnoreCase(parameterTested.substring(0,parameterTested.indexOf('/')))) {
					String currentUrl = request.getURL().getSHPP();
					int secondLast = currentUrl.lastIndexOf("/",currentUrl.length()-1);
					String newBaseUrl = currentUrl.substring(0, secondLast+1);
					try {
						HttpUrl urlWithNoParameters = new HttpUrl (newBaseUrl) ;
						_model.markAsXSSTested(id,urlWithNoParameters,parameterTested.substring(0,parameterTested.indexOf('/')),parameterTested.substring(parameterTested.indexOf('/')+1));
						
					} catch (MalformedURLException exception) {
						_logger.info("Error while getting url from "+currentUrl);
					}
				} else {
					_model.markAsXSSTested(id,request.getURL(),parameterTested.substring(0,parameterTested.indexOf('/')),parameterTested.substring(parameterTested.indexOf('/')+1));
				}
				// Tagging conversation with the value tried in the request
				_model.setXSSValueTried(id);
			}
			
		} else {
			parameterTested = "NOT FROM THIS REQUEST";
		}
		
		
		if (reAnalyse) {
			//id = response.getConversationID ();
			_logger.fine("Reanalysing response for conversation: "+id);
			if (id != null) {
				_logger.fine ("Verifying origin of conversation: "+id);
				String origin = _framework.getModel().getConversationOrigin(id);
				if (origin != null && ! origin.equalsIgnoreCase(getPluginName()) && fromPlugin) {
					// The conversation analysed is not from this plugin, so it is ignored
					_logger.fine ("Conversation "+id+" is not from this plugin, so not analysing it");
					return;
				} else {
					// Response will be analysed, so we get the request associated
					request = _model.getRequest(id);
				}
			} else {
				// The Conversation ID cannot be get, so we return
				return;
			}
		}
		_logger.fine ("Analysing response: "+id);

		Pattern pattern = Pattern.compile(patternToFind);
		Pattern patternPartial = Pattern.compile(patternToFindPartial);
		Matcher matcher = null;
		
		
		// 2011-12-13 - JLS - Calling getSpecificParametersOfRequest to simplify - BEGIN
		if (specificParameters != null) {
			String typeOfTest = specificParameters.get(headerTypeOfTest);
			if (typeOfTest != null && typeOfTest.startsWith("LongValue")) {
				return;
			}
		}
		/*
		// Check if parameter is for XSS or not
		HashMap<String,String> specificParameters = null;
		synchronized(specificParametersOfRequests) {
			specificParameters = specificParametersOfRequests.get(request);
		}
		if (specificParameters != null) {
			parameterTested = specificParameters.get(_headerParameterTested);
			String typeOfTest = specificParameters.get(headerTypeOfTest);
			if (typeOfTest != null && typeOfTest.startsWith("LongValue")) {
				return;
			}
		}
		*/
		// 2011-12-13 - JLS - Calling getSpecificParametersOfRequest to simplify - END
		
		for (int i=0; i<headers.length; i++) {
			matcher = pattern.matcher(headers[i].getValue());
			// Search the pattern of XSS injected parameter in the HEADERS
			// 2011-01-25 - JLS - Modifying the search to include the headers - BEGIN 
			if (matcher.find()) {
				setXSSinResponse(matcher, id, response, "header", headers[i].getName(), false);
				xssFound = true;
			} else {
				matcher = patternPartial.matcher(headers[i].getValue());
				if (matcher.find()) {
					setXSSinResponse (matcher, id, response, "header", headers[i].getName(), true);
					xssFound = true;
				} else {
						_logger.finer("Response "+id+" does not match to XSS in header " + headers[i].getName());
					}
			}
			// 2011-01-25 - JLS - Modifying the search to include the headers - END
		}
		
				
		// 2011-07-13 - JLS - Better XSS detection - BEGIN
		String injectionFound = null;
		String injectionCharsFound = null;
		StringBuilder injectionToLog = new StringBuilder();
		Boolean injectionAsNewElementFound = Boolean.FALSE;
		Boolean injectionInTextOfElementFound = Boolean.FALSE;
		Boolean injectionNewTagInElementTextFound = Boolean.FALSE;
		Boolean injectionInElementFound = Boolean.FALSE;
		Boolean injectionInElementEscapableFound = Boolean.FALSE;
		Boolean injectionInElementColon = Boolean.FALSE;
		int injectionCapability = 0;
		String logPrefix = "ID: " + id + " ";
		Vector<String> patternsFoundKO = new Vector<String>(); 
		// Response might be valid to be analyzed
		String newResponseContent = body;
		if (newResponseContent == null || "".equals(newResponseContent)) {
			_logger.fine("Response is null or empty. Analysis finished.");
			return;
		}
		// Pattern to find. NOTE: The "." before PREFIX tag is IMPORTANT, as it is used to determine simply if the injection can escape or not
		Pattern patternOfInjectionInResponse = Pattern.compile("(?si).*(.EDW-[0-9]+[^_]*_EDW|.EDW-[0-9]+[^_]{1,60}|.EDW-[0-9]+[^EDW]*_EDW).*");
		Pattern patternOfInjectionInResponseText = Pattern.compile("(?si).*(EDW-[0-9]+[^_]*_EDW|EDW-[0-9]+[^_]{1,60}|EDW-[0-9]+[^EDW]*_EDW).*");
		Matcher matcherOfInjectionInResponse = null;
		
		Document doc = Jsoup.parse(newResponseContent);
		// 2013-03-06 - JLS - No formatting of the output - BEGIN
		doc.outputSettings().prettyPrint(Boolean.FALSE);
		//doc.outputSettings().escapeMode(Entities.EscapeMode.nada);
		// 2013-03-06 - JLS - No formatting of the output - END
		
		Elements elementsToAnalyze = doc.select("*");
		for (Element element : elementsToAnalyze) {
			Element currentElement = element.clone();
			// Check if current element has a special tag corresponding to the one injected
			String nodeName = currentElement.nodeName();
			if (nodeName != null && nodeName.equalsIgnoreCase(patternHtmlTag)) {
				injectionAsNewElementFound = Boolean.TRUE;
				_logger.info(logPrefix + "Found Injection as HTML TAG <"+nodeName+">, seen as a valid Tag by Jsoup. Try directly <script>.");
				//_logger.info(logSuffix + "-> Try directly <script>.");
				injectionToLog.append("<");
				injectionToLog.append(nodeName);
				injectionToLog.append(">");
				injectionToLog.append("|");
			}
			
			// Check child nodes which are not blocks (like text) and might contain the pattern
			List<Node> childs=currentElement.childNodes();
			for (int i=0;i<childs.size();i++) {
				// Only analyze #... blocks
				if (childs.get(i).nodeName().startsWith("#")) {
					String currentChildString = null;
					if (childs.get(i) instanceof TextNode) {
						currentChildString = ((TextNode) childs.get(i)).text();
					} else { 
						currentChildString = childs.get(i).toString();
					}
					_logger.finer(logPrefix + "CurrentChildString: "+currentChildString);
					matcherOfInjectionInResponse = patternOfInjectionInResponseText.matcher(currentChildString);
					// If current child (string representation) contains the pattern
					if (matcherOfInjectionInResponse.matches()) {
						_logger.finer(logPrefix + "CurrentChildString MATCHES pattern.");
						// Found an injection in the text of an Element (e.g <h1>Injection string</h1>)
						injectionInTextOfElementFound = Boolean.TRUE;
						
						// Clone the current Element to empty it without modifying the real Jsoup tree
						Element emptyElement = currentElement.clone();
						emptyElement.empty();
						//out.println("Found Injection in TEXT of Element: "+emptyElement.toString());
						
						// If injection worked fully, patternHtmlTag is next Sibling, so put all together
						Node nextSibling = childs.get(i).nextSibling();
						if (nextSibling != null && childs.get(i).nextSibling().nodeName().equalsIgnoreCase(patternHtmlTag)) {
							injectionFound = currentChildString + childs.get(i).nextSibling().toString().replaceAll("(?s)\\r","").replaceAll("(?s)\\n","").replaceAll("(?s)</"+childs.get(i).nextSibling().nodeName()+">$","");
							_logger.fine(logPrefix + "Found correspond injected tag: "+injectionFound);
						} else {
							// Check if an HTML tag (e.g <script>) can be created
							injectionFound = matcherOfInjectionInResponse.group(1);
							//out.println("-> Text found: " + injectionFound);
						}
						
						injectionCharsFound = getCharsInjected(removeEntities(injectionFound));
						// If "<" AND ">" can be injected, creation of a new tag should be possible
						if (injectionCharsFound.indexOf('>') >=0 && injectionCharsFound.indexOf('<') >=0)
						{
							// New tag is possible
							injectionNewTagInElementTextFound = Boolean.TRUE;
							injectionToLog.append(injectionFound);
							injectionToLog.append('|');
							_logger.info(logPrefix + "Found Injection in TEXT of Element: "+emptyElement.toString() + ". Try directly: <script>");
							//_logger.info(logSuffix + "-> Text found: " + injectionFound.trim());
							//_logger.info(logSuffix + "-> Try directly: <script>");
						} else {
							if ((injectionCharsFound.replaceAll(String.valueOf(charToRepeat),"").length()) > 0) {
								_logger.fine(logPrefix + "Found pattern in TEXT of Element: "+emptyElement.toString());
								_logger.fine(logPrefix + "-> Text found: " + injectionFound);
								_logger.fine(logPrefix + "-> Creation of a new TAG does NOT seem possible.");
								_logger.fine(logPrefix + "-> Permitted chars are: "+injectionCharsFound);
								// 2013-07-04 - JLS - Test if injection is within a script - BEGIN
								if (emptyElement.toString().toUpperCase().indexOf("SCRIPT")>=0) {
									_logger.info(logPrefix + "Found pattern in TEXT of a script: "+emptyElement.toString());
									_logger.info(logPrefix + "-> Text found: " + injectionFound);
									_logger.info(logPrefix + "-> Permitted chars are: "+injectionCharsFound);
									injectionInElementFound = Boolean.TRUE;
									injectionToLog.append(injectionFound);
									injectionToLog.append('|');
								}
								// 2013-07-04 - JLS - Test if injection is within a script - END
							}
						}
					}
				} else {
				String currentChildString = childs.get(i).toString();
				_logger.finer(logPrefix + "CurrentChildString is NORMAL element: "+currentChildString);
				//_logger.finer("Matches? "+ currentChildString.matches("(?si).*(EDW-[0-9]+[^_]*_EDW|EDW-[0-9]+[^_]{1,60}).*"));
				}

			}
			// Analysis of the childs of the current Node is done, so analysis is performed only on the current Element
			currentElement.empty();
			_logger.finest(logPrefix + "Analyzing currentElement: "+currentElement.toString());
			matcherOfInjectionInResponse = patternOfInjectionInResponse.matcher(currentElement.toString());
			// Pattern is present in the HTML element (in tag name, attribute name or an attribute value)
			if (matcherOfInjectionInResponse.matches()) {
				injectionFound = matcherOfInjectionInResponse.group(1);
				injectionInElementFound = Boolean.TRUE;
				injectionCharsFound = getCharsInjected(injectionFound.substring(1));
				// If first character is also present in injected String, the injection can modify the Element itself
				if (checkPossibleEscape(injectionFound, injectionFound.charAt(0))) {
					_logger.info(logPrefix + "Found EDW in Element: " + currentElement);
					_logger.info(logPrefix + "-> Text found: " + injectionFound);
					
					if (injectionCharsFound.indexOf('>') >=0 && injectionCharsFound.indexOf('<') >=0)
					{
						injectionInElementEscapableFound = Boolean.TRUE;
						injectionToLog.append(injectionFound);
						injectionToLog.append("|");
						_logger.info(logPrefix + "-> Escape and new TAG is POSSIBLE.");
					} else {
						_logger.info(logPrefix + "-> Escape is possible but NOT the creation of a new TAG.");
					}
				} else {
					_logger.fine(logPrefix + "Found EDW in Element but it is NOT escapable");
					_logger.fine(logPrefix + "Pattern found is: " + matcherOfInjectionInResponse.group(1));
					patternsFoundKO.add(matcherOfInjectionInResponse.group(1).substring(1));
					if (injectionCharsFound.indexOf(':') >= 0) {
						_logger.info(logPrefix + "Character ':' is permitted, maybe try javascript:alert('XSS') ???");
						injectionInElementColon = Boolean.TRUE;
					}
				}
			}
		}
		// Check directly with text
		patternOfInjectionInResponseText = Pattern.compile("(?si).*(.{0,50})(EDW-[0-9]+[^_]*_EDW|EDW-[0-9]+[^_]{1,60}|EDW-[0-9]+[^EDW]*_EDW)(.{0,50}).*");
		matcherOfInjectionInResponse = patternOfInjectionInResponseText.matcher(newResponseContent);
		if (matcherOfInjectionInResponse.matches()) {
				injectionFound = matcherOfInjectionInResponse.group(2);
				_logger.fine(logPrefix + "Found EDW in raw text, VERIFYING if declared as simple text by jsoup.");
				Boolean found = Boolean.FALSE;
				for (int i=0; i < patternsFoundKO.size(); i++) {
					if (injectionFound.equals(patternsFoundKO.get(i))) {
						found = Boolean.TRUE;
					}
				}
				if (!found) {
					// Test for potential injection
					String caractersFound = checkInjectabilityOfString(injectionFound, injectionInElementEscapableFound);
					if (!caractersFound.isEmpty()) {
						_logger.info(logPrefix + "Found Injection in RAW TEXT, these caracters are injectable: " + caractersFound);
						_logger.info(logPrefix + "-> Context is: " + matcherOfInjectionInResponse.group(1) + matcherOfInjectionInResponse.group(2) + matcherOfInjectionInResponse.group(3));
						injectionToLog.append(injectionFound);
						injectionToLog.append("|");
					}
				}
		}
		
		if (injectionInTextOfElementFound) {
			xssFound = true;
			injectionCapability++;
		}
		if (injectionNewTagInElementTextFound) {
			injectionCapability = injectionCapability + 12;
			xssFound = true;
		}
		if (injectionInElementFound) {
			injectionCapability = injectionCapability + 3;
			xssFound = true;
			if (injectionInElementColon) {
				injectionCapability = injectionCapability + 2;
			}
		}
		if (injectionInElementEscapableFound) {
			injectionCapability = injectionCapability + 8;
			xssFound = true;
		}
		if (injectionAsNewElementFound) {
			injectionCapability = injectionCapability + 10;
			xssFound = true;
		}
		
		if (xssFound) {
			if (injectionCapability >5) {
				_logger.info(logPrefix + "-> Injection capability of Request " + id + " is : "+injectionCapability);
				injectionToLog.insert(0,new String (injectionCapability+":"));
				setXSSinResponse (injectionToLog.toString(), id, response, "body", parameterTested, false);
			} else if (injectionCapability <5 && injectionCapability >0) {
				//setXSSinResponse (injectionToLog.toString(), id, response, "body", parameterTested, true);
			} 
		}

		
		// 2011-07-13 - JLS - Better XSS detection - END
		
		// 2011-01-13 - JLS - Adding correct pattern matching - END
		// 2011-03-15 - JLS - Adding a flag to know if a XSS vulnerability has been found or not - BEGIN
		// Only unset if it is a new analysis, as it is the first response received, it won't be flagged as XSSVulnerable
		if (!xssFound && reAnalyse) {
			_model.unsetXSSVulnerable (id,request.getURL());
		}
		// 2011-03-15 - JLS - Adding a flag to know if a XSS vulnerability has been found or not - END
	}
	

	public String checkInjectabilityOfString(final String stringFound, Boolean isEscapable) {
		StringBuilder returnedCharsFound = new StringBuilder();
		String caractersFound = getCharsInjected(removeEntities(stringFound));
		
		// If "<" AND ">" can be injected, creation of a new tag should be possible
		if (caractersFound.indexOf('>') >=0 && caractersFound.indexOf('<') >=0)
		{
			// New tag is possible
			_logger.fine("Found Injection in TEXT: "+stringFound);
			_logger.fine("Found possibility to inject caracters '<' and '>'");
			_logger.fine("-> Try directly: <script>");
			returnedCharsFound.append("<>");
		}
		if (caractersFound.indexOf('\'') >=0)
		{
			_logger.fine("Found potential escape in TEXT: "+stringFound);
			_logger.fine("Found possibility to inject caracter '''");
			returnedCharsFound.append("'");
			isEscapable = Boolean.TRUE;
		}
		
		if (caractersFound.indexOf('"') >=0)
		{
			_logger.fine("Found potential escape in TEXT: "+stringFound);
			_logger.fine("Found possibility to inject caracter '\"'");
			returnedCharsFound.append("\"");
			isEscapable = Boolean.TRUE;
		}
		return returnedCharsFound.toString();
		
	}

	// 2011-12-09 - JLS - Adding a check if response has a Request associated - BEGIN
	// Maybe should be placed in Framwork ??,
	public Request getAssociatedRequest(Response response) {
		Request request = null;
		if (response == null) {
			_logger.warning("Null response received.");
		} else {
			request = response.getRequest();
		}
		// Try via _model
		/*
		if (request == null) {
			ConversationID id = response.getConversationID();
			request = _model.getRequest(id);
		}
		*/
		return(request);
	}
	// 2011-12-09 - JLS - Adding a check if response has a Request associated - END
	
	public void responseReceivedWithReanalyse(Response response, Boolean reAnalyse) {
		// 2011-12-09 - JLS - Adding a check if response has a Request associated - BEGIN
		Request request = response.getRequest();
		ConversationID id = null;
		if (request == null) {
			_logger.severe ("No request associated with response received. Aborting analysis of the response.");
			return;
		}
		_logger.fine("Request associated with the response has been found.");
		// 2011-12-09 - JLS - Adding a check if response has a Request associated - END
		
		// Add the conversation to the framework if not reAnalyse
		if (! reAnalyse) {
			_logger.fine("Adding conversation to framework.");
			id = _framework.addConversation(request, response, getPluginName());
			_logger.fine("Conversation added, id is: " + id);
		} else {
			_logger.warning("Not IMPLEMENTED!!!!");
			return;
			//id = response.getConversationID ();
		}

		_logger.fine("Calling analysis plugins.");
		
		// Must check if from plugin as it can be called again and/or later
		Boolean fromPlugin = _framework.getModel().getConversationOrigin(id).equals(getPluginName());

		checkForXSSInResponse(response, id, reAnalyse, fromPlugin);
		checkForSQLiInResponse(response, reAnalyse, fromPlugin);
		if (! reAnalyse) {
			_model.oneMoreRequestAnalyzed();
		}
	}


	public void requestError(Request request, IOException ioe) {
		
	}
	
	public void setSession(String type, Object store, String session) throws StoreException {
	}
	
	public boolean stop() {
		_logger.info("Stopping XSS-ng");
		/*
		try {
			flush();
		} catch (StoreException exception) {
			_logger.severe("Error during flushing: " + exception.toString());
		}
		*/
		_model.setStopping(true);
		_model.setRunning(false);
		return _model.isRunning();
	}
	
	
	public XSSCRLFngModel getModel() {
		return _model;
	}
	
	public void stopChecks() {
		// Stop checks, let the other thread return ASAP
		_logger.info("stopChecks()");
	}
	
	public synchronized String loadString(File file) throws IOException {
		StringBuffer buf = new StringBuffer();
		String line;
		
		BufferedReader input = new BufferedReader(new FileReader(file));
		
		while ((line = input.readLine()) != null) {
			buf.append(line);
		}
		
		return buf.toString();
	}    
	// 2011-07-07 - JLS - Modifying order of calls - BEGIN
	public void checkSelected (ConversationID []ids) {
		Request req = null;
		Response response = null;
		for (int j=0; j < ids.length; j++) {
			req = _model.getRequest(ids[j]);
			response = _model.getResponse(ids[j]);
			//analyse(ids[j], req, response, "User", Boolean.TRUE);
			submitXSSngTest(ids[j], req, response, "User", Boolean.TRUE);
			
		}
	}
	
	
	public void checkSelected (ConversationID id) {
		Request req = null;
		Response response = null;
		req = _model.getRequest(id);
		response = _model.getResponse(id);
		submitXSSngTest(id, req, response, "User", Boolean.TRUE);
	}
	// 2011-07-07 - JLS - Modifying order of calls - END
	public boolean activateSelected () {
 		_testAll = !_testAll;
 		_logger.finest("Button Activate/Deactivate clicked. Activation is now: "+_testAll);
 		return (_testAll);
	}
	
	public boolean testAll () {
		return (_testAll);
	}

	
	// 2011-07-26 - JLS - Adding a button for SQLi tests - BEGIN
	public boolean doSQLiTests() {
		return (_doSQLiTests);
	}
	
	public boolean switchSQLiTests () {
 		_doSQLiTests = !_doSQLiTests;
 		_logger.fine("Button Activate/Deactivate SQLi tests clicked. Activation is now: "+_doSQLiTests);
 		return (_doSQLiTests);
	}

	// 2011-07-26 - JLS - Adding a button for SQLi tests - END
	
	private String getParametersWithTestString(String content, String name, String value) {
		StringBuffer buf = new StringBuffer("");
		
		NamedValue[] params = NamedValue.splitNamedValues(content, "&", "=");
		for (int i=0; i < params.length; i++) {
			// 2011-07-11 - JLS - Append characters as characters and not strings - BEGIN
			buf.append(params[i].getName());
			buf.append('=');
			if (params[i].getName().equals(name)) {
				buf.append(value);
			} else {
				buf.append(params[i].getValue());
			}
			if (i < params.length-1) {
				buf.append('&');
			}
			// 2011-07-11 - JLS - Append characters as characters and not strings - END
		}
		return buf.toString();
	}
	


	
}
