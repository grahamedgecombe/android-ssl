package uk.ac.cam.gpe21.droidssl.analysis.util;

import soot.RefType;
import soot.SootMethod;
import soot.Type;

public final class Signatures {
	public static boolean methodSignatureMatches(SootMethod method, RefType clazzType, Type returnType, String name, Type... parameterTypes) {
		if (!method.getDeclaringClass().getType().equals(clazzType))
			return false;

		return methodSignatureMatches(method, returnType, name, parameterTypes);
	}

	public static boolean methodSignatureMatches(SootMethod method, Type returnType, String name, Type... parameterTypes) {
		if (!method.getName().equals(name))
			return false;

		return methodSignatureMatches(method, returnType, parameterTypes);
	}

	public static boolean methodSignatureMatches(SootMethod method, Type returnType, Type... parameterTypes) {
		if (!method.getReturnType().equals(returnType))
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
