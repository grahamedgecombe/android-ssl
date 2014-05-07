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

import soot.SceneTransformer;
import uk.ac.cam.gpe21.droidssl.analysis.Vulnerability;

import java.util.Map;
import java.util.Set;

public final class AnalysisTransformer extends SceneTransformer {
	private final Set<Vulnerability> vulnerabilities;
	private final Analyser[] analysers;

	public AnalysisTransformer(Set<Vulnerability> vulnerabilities, Analyser... analysers) {
		this.vulnerabilities = vulnerabilities;
		this.analysers = analysers;
	}

	@Override
	protected void internalTransform(String phase, Map<String, String> options) {
		int size;
		do {
			size = vulnerabilities.size();
			for (Analyser analyser : analysers) {
				analyser.analyse();
			}
		} while (size != vulnerabilities.size());
	}
}
