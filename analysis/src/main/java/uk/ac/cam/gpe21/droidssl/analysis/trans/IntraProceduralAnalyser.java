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

package uk.ac.cam.gpe21.droidssl.analysis.trans;

import soot.Body;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import uk.ac.cam.gpe21.droidssl.analysis.Vulnerability;

import java.util.Set;

public abstract class IntraProceduralAnalyser extends Analyser {
	public IntraProceduralAnalyser(Set<Vulnerability> vulnerabilities) {
		super(vulnerabilities);
	}

	@Override
	public void analyse() {
		for (SootClass clazz : Scene.v().getApplicationClasses()) {
			for (SootMethod method : clazz.getMethods()) {
				if (!method.isConcrete())
					continue;

				Body body = method.retrieveActiveBody();
				analyse(clazz, method, body);
			}
		}
	}

	protected abstract void analyse(SootClass clazz, SootMethod method, Body body);
}
