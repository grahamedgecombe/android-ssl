package uk.ac.cam.gpe21.droidssl.mitm.ui.gui;

import javax.swing.*;
import java.awt.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Contains UI-related utility methods.
 * @author Graham Edgecombe
 */
public final class UiUtils {
	private static final Logger logger = Logger.getLogger(UiUtils.class.getName());

	public static void setNativeLookAndFeel() {
		try {
			String clazz = UIManager.getSystemLookAndFeelClassName();

			/*
			 * on Linux, the Java library only uses the GTK+ style iff
			 * the desktop environment is GNOME. This tries to use GTK+
			 * in any case, as there are many other DEs (XFCE, LXDE,
			 * Unity, etc.) using GTK+, and even ones that don't (e.g.
			 * KDE) often have a compatibility theme installed so it
			 * still looks good.
			 */
			if (clazz.equals(UIManager.getCrossPlatformLookAndFeelClassName()) && System.getProperty("os.name").contains("Linux"))
				clazz = "com.sun.java.swing.plaf.gtk.GTKLookAndFeel";

			UIManager.setLookAndFeel(clazz);
		} catch (ClassNotFoundException | InstantiationException | IllegalAccessException | UnsupportedLookAndFeelException ex) {
			logger.log(Level.WARNING, "Failed to switch to system look and feel:", ex);
		}
	}

	public static void positionInCenter(Window window) {
		GraphicsDevice screen = GraphicsEnvironment.getLocalGraphicsEnvironment().getDefaultScreenDevice();
		GraphicsConfiguration configuration = screen.getDefaultConfiguration();

		Rectangle bounds = configuration.getBounds();
		int x = (int) bounds.getCenterX() - window.getWidth() / 2;
		int y = (int) bounds.getCenterY() - window.getHeight() / 2;

		window.setLocation(x, y);
	}

	private UiUtils() {
		/* to prevent insantiation */
	}
}
