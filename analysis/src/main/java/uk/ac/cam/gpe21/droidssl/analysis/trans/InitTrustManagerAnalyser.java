package uk.ac.cam.gpe21.droidssl.analysis.trans;

import soot.*;
import soot.jimple.AbstractJimpleValueSwitch;
import soot.jimple.NewExpr;
import uk.ac.cam.gpe21.droidssl.analysis.Vulnerability;
import uk.ac.cam.gpe21.droidssl.analysis.VulnerabilityType;
import uk.ac.cam.gpe21.droidssl.analysis.tag.TrustManagerTag;

import java.util.Set;

public final class InitTrustManagerAnalyser extends IntraProceduralAnalyser {
	public InitTrustManagerAnalyser(Set<Vulnerability> vulnerabilities) {
		super(vulnerabilities);
	}

	@Override
	protected void analyse(SootClass clazz, final SootMethod method, Body body) {
		for (Unit unit : body.getUnits()) {
			for (ValueBox valueBox : unit.getUseBoxes()) {
				valueBox.getValue().apply(new AbstractJimpleValueSwitch() {
					@Override
					public void caseNewExpr(NewExpr value) {
						SootClass type = value.getBaseType().getSootClass();
						if (type.hasTag(TrustManagerTag.NAME)) {
							TrustManagerTag tag = (TrustManagerTag) type.getTag(TrustManagerTag.NAME);
							vulnerabilities.add(new Vulnerability(method, VulnerabilityType.INIT_TRUST_MANAGER, tag.getState()));
						}
					}
				});
			}
		}
	}
}
