/*
 * Copyright 2013-2014 Graham Edgecombe
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
