package uk.ac.cam.gpe21.droidssl.mitm.ui.gui;

import uk.ac.cam.gpe21.droidssl.mitm.ui.Session;

import javax.swing.*;
import java.awt.*;

public final class SessionListCellRender implements ListCellRenderer<Session> {
	private final JLabel label = new JLabel();

	public SessionListCellRender() {
		label.setOpaque(true);
	}

	@Override
	public Component getListCellRendererComponent(JList<? extends Session> list, Session value, int index, boolean isSelected, boolean cellHasFocus) {
		label.setText(value.toString());

		if (isSelected) {
			label.setBackground(Color.BLUE);
		} else {
			label.setBackground(value.getState().getColor());
		}

		return label;
	}
}
