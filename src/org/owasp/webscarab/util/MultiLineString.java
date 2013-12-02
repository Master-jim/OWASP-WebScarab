package org.owasp.webscarab.util;
import java.lang.String;

public class MultiLineString{
	private static String replaceSeparator = "\n";
	public static final String defaultSeparator = "#-#";
	private String value = null;
	private String separator = defaultSeparator;

	public MultiLineString () {
	}
	public MultiLineString(String string) {
		value = string;
		//return (this.toString());
	}
	public String MultiLineString(String string, String separator) {
		return (string.replaceAll(separator,replaceSeparator));
	}
	public String toString() {
		if (value != null) {
			return (value.replaceAll(separator,replaceSeparator));
		} else { 
			return ("");
		}
	}
	public String toString(String string) {
		value = string;
		if (value != null) {
			return (value.replaceAll(separator,replaceSeparator));
		} else { 
			return ("");
		}
	}

}
