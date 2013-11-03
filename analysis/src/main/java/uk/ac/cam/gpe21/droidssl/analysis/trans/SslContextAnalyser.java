package uk.ac.cam.gpe21.droidssl.analysis.trans;

import soot.Body;
import soot.SootClass;
import soot.SootMethod;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.UnitGraph;
import uk.ac.cam.gpe21.droidssl.analysis.Vulnerability;

import java.util.List;

public final class SslContextAnalyser extends Analyser {
	public SslContextAnalyser(List<Vulnerability> vulnerabilities) {
		super(vulnerabilities);
	}

	@Override
	protected void analyse(SootClass clazz, SootMethod method, Body body) {
		if (!method.getName().equals("connect"))
			return;

		UnitGraph graph = new BriefUnitGraph(body);
		SslContextFlowAnalysis analysis = new SslContextFlowAnalysis(graph);

		// TODO finish
	}
}
