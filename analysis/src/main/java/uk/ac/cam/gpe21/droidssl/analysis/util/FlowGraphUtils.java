package uk.ac.cam.gpe21.droidssl.analysis.util;

import soot.RefType;
import soot.Unit;
import soot.jimple.IntConstant;
import soot.jimple.ReturnStmt;
import soot.toolkits.exceptions.ThrowableSet;
import soot.toolkits.exceptions.UnitThrowAnalysis;
import soot.toolkits.graph.UnitGraph;

public final class FlowGraphUtils {
	public static boolean anyExitThrowsException(UnitGraph graph, RefType exceptionType) {
		for (Unit unit : graph.getTails()) {
			ThrowableSet set = UnitThrowAnalysis.v().mightThrow(unit);
			if (set.catchableAs(exceptionType)) {
				return true;
			}
		}

		return false;
	}

	public static boolean allExitsReturnTrue(UnitGraph graph) {
		for (Unit unit : graph.getTails()) {
			if (unit instanceof ReturnStmt) {
				ReturnStmt stmt = (ReturnStmt) unit;
				if (!stmt.getOp().equals(IntConstant.v(1))) {
					return false;
				}
			}
		}

		return true;
	}

	private FlowGraphUtils() {
		/* to prevent instantiation */
	}
}
