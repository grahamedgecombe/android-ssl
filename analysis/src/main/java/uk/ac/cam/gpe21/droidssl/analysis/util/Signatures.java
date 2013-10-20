package uk.ac.cam.gpe21.droidssl.analysis.util;

import soot.SootMethod;
import soot.Type;

public final class Signatures {
	public static boolean methodSignatureMatches(SootMethod method, Type returnType, String name, Type... parameterTypes) {
		if (!method.getReturnType().equals(returnType))
			return false;

		if (!method.getName().equals(name))
			return false;

		if (method.getParameterCount() != parameterTypes.length)
			return false;

		for (int i = 0; i < parameterTypes.length; i++) {
			if (!method.getParameterType(i).equals(parameterTypes[i]))
				return false;
		}

		return true;
	}

	private Signatures() {
		/* to prevent instantiation */
	}
}
