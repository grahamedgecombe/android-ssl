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

import soot.*;
import uk.ac.cam.gpe21.droidssl.analysis.VulnerabilityState;
import uk.ac.cam.gpe21.droidssl.analysis.tag.VulnerabilityTag;

public final class PointsToUtils {
	public static boolean anyTypeVulnerable(PointsToSet set, final String tagName) {
		final boolean[] box = new boolean[1]; // TODO this is hacky

		for (Type type : set.possibleTypes()) {
			type.apply(new TypeSwitch() {
				@Override
				public void caseRefType(RefType type) {
					VulnerabilityTag tag = (VulnerabilityTag) type.getSootClass().getTag(tagName);
					if (tag != null && tag.getState() == VulnerabilityState.VULNERABLE)
						box[0] = true;
				}

				@Override
				public void caseAnySubType(AnySubType type) {
					VulnerabilityTag tag = (VulnerabilityTag) type.getBase().getSootClass().getTag(tagName);
					if (tag != null && tag.getState() == VulnerabilityState.VULNERABLE)
						box[0] = true;
				}

				// TODO any other cases?
			});
		}

		return box[0];
	}

	public static boolean allTypesSafe(PointsToSet set, final String tagName) {
		final boolean[] box = new boolean[1]; // TODO this is hacky
		box[0] = true;

		for (Type type : set.possibleTypes()) {
			type.apply(new TypeSwitch() {
				@Override
				public void caseRefType(RefType type) {
					VulnerabilityTag tag = (VulnerabilityTag) type.getSootClass().getTag(tagName);
					if (tag != null && tag.getState() != VulnerabilityState.SAFE)
						box[0] = false;
				}

				@Override
				public void caseAnySubType(AnySubType type) {
					VulnerabilityTag tag = (VulnerabilityTag) type.getBase().getSootClass().getTag(tagName);
					if (tag != null && tag.getState() != VulnerabilityState.SAFE)
						box[0] = false;
				}

				// TODO any other cases?
			});
		}

		return box[0];
	}

	private PointsToUtils() {
		/* to prevent instantiation */
	}
}
