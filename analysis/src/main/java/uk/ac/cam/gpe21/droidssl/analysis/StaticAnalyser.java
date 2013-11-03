package uk.ac.cam.gpe21.droidssl.analysis;

import soot.*;
import soot.options.Options;

import java.util.Arrays;
import java.util.Map;

public final class StaticAnalyser {
	public static void main(String[] args) {
		/*
		 * Set path to input APK.
		 */
		Options.v().set_src_prec(Options.src_prec_apk);
		Options.v().set_process_dir(Arrays.asList("test-hv/build/apk/test-hv-release-unsigned.apk"));

		/*
		 * Prevent Soot from outputting *.jimple files.
		 */
		Options.v().set_output_format(Options.output_format_none);

		/*
		 * Set the path to the Android SDK.
		 */
		Options.v().set_android_jars("/opt/android/platforms");

		/*
		 * Enable the SPARK points-to analysis.
		 */
		Options.v().set_whole_program(true);
		PhaseOptions.v().processPhaseOptions("cg.spark", "enabled:true");

		/*
		 * Add transforms to the Whole Jimple Pre-processing Pack.
		 */
		Pack wjpp = PackManager.v().getPack("wjpp");
		wjpp.add(new Transform("wjpp.activity_entry_transformer", new ActivityEntryTransformer()));
		wjpp.add(new Transform("wjpp.known_vulnerable_class_tagger", new KnownVulnerableClassTagger()));

		/*
		 * Add transforms to the Jimple Transformation Pack.
		 */
		Pack jtp = PackManager.v().getPack("jtp");
		jtp.add(new Transform("jtp.jsse_hostname_verifier", new JsseHostnameVerifierTransformer()));
		jtp.add(new Transform("jtp.httpclient_hostname_verifier", new HttpClientHostnameVerifierTransformer()));
		jtp.add(new Transform("jtp.default_jsse_hostname_verifier", new DefaultJsseHostnameVerifierTransformer()));

		/*
		 * Add transforms for the Whole Jimple Transformation Pack.
		 */
		Pack wjtp = PackManager.v().getPack("wjtp");
		wjtp.add(new Transform("wjtp.print_call_graph", new SceneTransformer() {
			@Override
			protected void internalTransform(String phase, Map<String, String> options) {
				System.err.print(Scene.v().getCallGraph());
			}
		}));

		/*
		 * Perform the analysis.
		 */
		Scene.v().loadNecessaryClasses();
		PackManager.v().runPacks();
	}
}
