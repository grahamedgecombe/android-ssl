package uk.ac.cam.gpe21.droidssl.mitm.ui.gui;

import uk.ac.cam.gpe21.droidssl.mitm.ui.Session;
import uk.ac.cam.gpe21.droidssl.mitm.ui.UserInterface;
import uk.ac.cam.gpe21.droidssl.mitm.util.HexFormat;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import java.awt.*;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Map;

public final class GraphicalUserInterface extends UserInterface implements ListSelectionListener {
	private JFrame frame;
	private DefaultListModel<Session> sessionsModel;
	private JList<Session> sessions;
	private Map<Session, JTextArea> receiveData  = new HashMap<>();
	private Map<Session, JTextArea> transmitData = new HashMap<>();
	private Map<Session, JScrollPane> receiveScroll  = new HashMap<>();
	private Map<Session, JScrollPane> transmitScroll = new HashMap<>();
	private JTabbedPane tabs;

	private JLabel state, source, dest;
	private JTextArea exception;

	public GraphicalUserInterface() throws InvocationTargetException, InterruptedException {
		EventQueue.invokeAndWait(new Runnable() {
			@Override
			public void run() {
				UiUtils.setNativeLookAndFeel();

				frame = new JFrame("MITM");
				frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

				Container contentPane = frame.getContentPane();
				contentPane.setLayout(new BorderLayout());

				sessionsModel = new DefaultListModel<>();
				sessions = new JList<>(sessionsModel);
				sessions.setCellRenderer(new SessionListCellRender());
				sessions.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
				sessions.addListSelectionListener(GraphicalUserInterface.this);

				JScrollPane sessionsContainer = new JScrollPane(sessions);
				sessionsContainer.setMinimumSize(new Dimension(250, 0));
				sessionsContainer.setMaximumSize(new Dimension(250, Integer.MAX_VALUE));
				sessionsContainer.setPreferredSize(new Dimension(250, 0));
				contentPane.add(sessionsContainer, BorderLayout.WEST);

				JPanel info = new JPanel();
				info.setLayout(new GridLayout(0, 2));

				info.add(new JLabel("State:"));
				info.add(state = new JLabel("-"));

				info.add(new JLabel("Source:"));
				info.add(source = new JLabel("-"));

				info.add(new JLabel("Destination:"));
				info.add(dest = new JLabel("-"));

				JPanel infoContainer = new JPanel();
				infoContainer.setLayout(new BorderLayout());
				infoContainer.add(BorderLayout.NORTH, info);

				exception = new JTextArea();
				exception.setOpaque(false);
				exception.setEditable(false);
				infoContainer.add(BorderLayout.CENTER, exception);

				tabs = new JTabbedPane();
				tabs.add("Info", infoContainer);
				tabs.add("Device -> Server", new JPanel());
				tabs.add("Server -> Device", new JPanel());
				tabs.setEnabledAt(1, false);
				tabs.setEnabledAt(2, false);

				contentPane.add(tabs, BorderLayout.CENTER);

				frame.setSize(1024, 768);
				UiUtils.positionInCenter(frame);
				frame.setVisible(true);
				frame.toFront();
			}
		});
	}

	@Override
	public void onOpen(final Session session) {
		EventQueue.invokeLater(new Runnable() {
			@Override
			public void run() {
				Font font = new Font(Font.MONOSPACED, Font.PLAIN, 12);

				JTextArea receiveText = new JTextArea();
				receiveText.setEditable(false);
				receiveText.setFont(font);

				JTextArea transmitText = new JTextArea();
				transmitText.setEditable(false);
				transmitText.setFont(font);

				receiveData.put(session, receiveText);
				transmitData.put(session, transmitText);

				receiveScroll.put(session, new JScrollPane(receiveText));
				transmitScroll.put(session, new JScrollPane(transmitText));

				sessionsModel.addElement(session);
			}
		});
	}

	@Override
	public void onData(final Session session, final boolean receive, final byte[] buf, final int len) {
		EventQueue.invokeLater(new Runnable() {
			@Override
			public void run() {
				JTextArea textArea;
				if (receive) {
					textArea = receiveData.get(session);
				} else {
					textArea = transmitData.get(session);
				}

				textArea.append(HexFormat.format(buf, len));
				textArea.append("\n\n");
			}
		});
	}

	@Override
	public void onClose(final Session session) {
		EventQueue.invokeLater(new Runnable() {
			@Override
			public void run() {
				sessions.repaint();
				if (session == sessions.getSelectedValue()) {
					valueChanged(null); // TODO a bit hacky
				}
			}
		});
	}

	@Override
	public void onFailure(final Session session, IOException reason) {
		EventQueue.invokeLater(new Runnable() {
			@Override
			public void run() {
				sessions.repaint();
				if (session == sessions.getSelectedValue()) {
					valueChanged(null); // TODO a bit hacky
				}
			}
		});
	}

	@Override
	public void valueChanged(ListSelectionEvent evt) {
		Session session = sessions.getSelectedValue();
		if (session == null) {
			exception.setText("");

			state.setOpaque(false);
			state.setText("-");

			source.setText("-");

			dest.setText("-");

			tabs.setEnabledAt(1, false);
			tabs.setEnabledAt(2, false);
		} else {
			Session.State state = session.getState();
			if (state == Session.State.FAILED) {
				try (StringWriter buf = new StringWriter();
					 PrintWriter writer = new PrintWriter(buf)) {
					session.getFailureReason().printStackTrace(writer);
					exception.setText(buf.toString());
				} catch (IOException ex) {
					/* ignore - can never happen */
				}
			} else {
				exception.setText("");
			}

			this.state.setOpaque(true);
			this.state.setText(state.toString());
			this.state.setBackground(state.getColor());

			InetSocketAddress sourceAddr = session.getSource();
			source.setText(sourceAddr.getAddress().getHostAddress() + ":" + sourceAddr.getPort() + " (" + sourceAddr.getHostName() + ")");

			InetSocketAddress destAddr = session.getDestination();
			dest.setText(destAddr.getAddress().getHostAddress() + ":" + destAddr.getPort() + " (" + destAddr.getHostName() + ")");

			tabs.setComponentAt(1, receiveScroll.get(session));
			tabs.setComponentAt(2, transmitScroll.get(session));

			tabs.setEnabledAt(1, true);
			tabs.setEnabledAt(2, true);

			tabs.repaint();
		}
	}
}
