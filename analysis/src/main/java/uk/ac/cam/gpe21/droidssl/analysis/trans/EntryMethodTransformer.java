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

import soot.Scene;
import soot.SceneTransformer;
import soot.SootClass;
import soot.SootMethod;

import java.util.Map;

public final class EntryMethodTransformer extends SceneTransformer {
	@Override
	protected void internalTransform(String phase, Map<String, String> options) {
		for (SootClass clazz : Scene.v().getApplicationClasses()) {
			for (SootMethod method : clazz.getMethods()) {
				if (method.isConcrete()) {
					Scene.v().getEntryPoints().add(method);
				}
			}
		}
	}
}
