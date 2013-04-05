package org.owasp.webscarab.plugin.xsscrlfng.swing;

public class MultiLineString{
	private static final String NEWLINE = "\n";
	private static final String DEFAULT_SEPARATOR = "#-#";
	private String value = null;

	public MultiLineString(final String text) {
		if (null != text) {
			value = text;
		}
	}
	
	public static String transform(final String string, final String separator) {
		String returnValue = "";
		
		if (null != string) {
			returnValue = string.replaceAll(DEFAULT_SEPARATOR,separator);
		}  
		return returnValue;
	}
	
	public String toString() {
		return transform(value, NEWLINE);
	}
	
	public String toString(final String string) {
		return transform(string, NEWLINE);
	}

	public static String getDefaultSeparator() {
		return DEFAULT_SEPARATOR;
	}
}
