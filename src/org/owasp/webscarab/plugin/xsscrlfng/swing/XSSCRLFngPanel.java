package org.owasp.webscarab.plugin.xsscrlfng.swing;

import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
import java.util.Date;
import java.util.logging.Logger;
import javax.swing.Action;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.TableModel;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.Preferences;
import org.owasp.webscarab.plugin.xsscrlfng.XSSCRLFng;
import org.owasp.webscarab.plugin.xsscrlfng.XSSCRLFngModel;
import org.owasp.webscarab.ui.swing.ColumnWidthTracker;
import org.owasp.webscarab.ui.swing.ConversationTableModel;
import org.owasp.webscarab.ui.swing.DateRenderer;
import org.owasp.webscarab.ui.swing.ShowConversationAction;
import org.owasp.webscarab.ui.swing.SwingPluginUI;
import org.owasp.webscarab.util.swing.ColumnDataModel;
import org.owasp.webscarab.util.swing.SwingWorker;
import org.owasp.webscarab.util.swing.TableSorter;
import org.owasp.webscarab.model.ConversationID;

// JLS - 2010-07-21 - Adding actions
import javax.swing.AbstractAction;
//import java.awt.event.ActionListener;
//import java.awt.event.ActionEvent;
//import org.owasp.webscarab.model.Request;
//import org.owasp.webscarab.model.Response;

//2011-01-21 - JLS - Adding support of multiline for injected values - BEGIN
import org.owasp.webscarab.util.MultiLineString;
//2011-01-21 - JLS - Adding support of multiline for injected values - END

// 2011-03-14 - JLS - Adding a reAnalyse All button - BEGIN
import org.owasp.webscarab.model.ConversationModel;
// 2011-03-14 - JLS - Adding a reAnalyse All button - END

// 2011-03-14 - JLS - Huge ugly hack to support multiline in conversation table model - BEGIN
import org.owasp.webscarab.util.swing.MultiLineCellRenderer;
//import org.owasp.webscarab.util.MultiLineString;
// 2011-03-14 - JLS - Huge ugly hack to support multiline in conversation table model - END


// 2011-07-29 - JLS - Adding a progress bar - BEGIN
import javax.swing.JProgressBar;
import java.util.Timer;
import java.util.TimerTask;
// 2011-07-29 - JLS - Adding a progress bar - END
/**
*
* @author  jeremylebourdais
*/
public class XSSCRLFngPanel extends javax.swing.JPanel implements SwingPluginUI {
	
	/**
	* 
	*/
	private static final long serialVersionUID = -5862303750441463107L;
	private XSSCRLFng _xsscrlf;
	private XSSCRLFngModel _model;
	
	private Logger _logger = Logger.getLogger(getClass().getName());
	
	private ColumnDataModel[] _vulnerableConversationColumns;
	
	private ColumnDataModel[] _vulnerableUrlColumns;
	
	private ShowConversationAction _showAction;

	// JLS - 2010-07-21 - Adding actions
	private Action[] _conversationActions;
	
	// 2011-07-29 - JLS - Adding a progress bar - BEGIN
	private static JProgressBar _progressBar = null;
	private final Runnable doUpdateProgressBar = new Runnable() {
		public void run() {
			_progressBar.setValue(_model.getPercentageDone());
		}
	};
	
	TimerTask doUpdateProgressBarTimerTask = new TimerTask() {
		public void run() {
			java.awt.EventQueue.invokeLater(doUpdateProgressBar);
		}
	};
	private static Timer doUpdateProgressBarTimer = new Timer();
	// 2011-07-29 - JLS - Adding a progress bar - END
	// 2011-12-13 - JLS - Possibility to abort analysis - BEGIN
	protected Boolean reCheckIsFinishedOrAborted = Boolean.TRUE;
	// 2011-12-13 - JLS - Possibility to abort analysis - END
	
	/** Creates new form XSSCRLFPanel */
	public XSSCRLFngPanel(XSSCRLFng xsscrlf) {
		_xsscrlf = xsscrlf;
		_model = xsscrlf.getModel();
		initComponents();
		
		_vulnerableConversationColumns = new ColumnDataModel[2];
		ConversationTableModel vtm = new ConversationTableModel(_model.getVulnerableConversationModel());
		_vulnerableConversationColumns = new ColumnDataModel[] {
			new ColumnDataModel<ConversationID>("XSS-ng", Boolean.class) {
				public Object getValue(final ConversationID key) {
					return _model.isXSSVulnerable(key) ? Boolean.TRUE : Boolean.FALSE;
				}
			},
			new ColumnDataModel<ConversationID>("XSS-ng Parameter", String.class) {
				public Object getValue(final ConversationID key) {
					return _model.getXSSTested(key);
				}
			}
			// 2011-01-21 - JLS - Adding parameter vulnerable found - BEGIN
			,
			new ColumnDataModel<ConversationID>("XSS-ng Tested Parameter", String.class) {
				public Object getValue(final ConversationID key) {
					return _model.getXSSParamTested(key);
				}
			}
 			// 2011-01-21 - JLS - Adding parameter vulnerable found - END

 			// 2011-01-21 - JLS - Adding the injected parameter vulnerable found - BEGIN
			,
			new ColumnDataModel<ConversationID>("XSS-ng Injected Parameter Found", MultiLineString.class) {
				public Object getValue(final ConversationID key) {
					return new MultiLineString(_model.getXSSParamVulnerableInjected(key));
				}
			}
 			// 2011-01-21 - JLS - Adding the injected parameter vulnerable found - END
		};
		vtm.addColumn(_vulnerableConversationColumns[0]);
		
		vtm.addColumn(_vulnerableConversationColumns[2]);
		
		vtm.addColumn(_vulnerableConversationColumns[3]);
		
		ConversationTableModel stm = new ConversationTableModel(_model.getSuspectedConversationModel());
		stm.addColumn(new ColumnDataModel<ConversationID>("XSS-ng2", Boolean.class) {
				public Object getValue(final ConversationID key) {
					return _model.isXSSTested(key) ? Boolean.TRUE : Boolean.FALSE;
				}
		});
		// 2011-03-15 - JLS - Modifying rows showed in XSS panel - BEGIN
		stm.addColumn(_vulnerableConversationColumns[1]);
/* 		stm.addColumn(new ColumnDataModel() {
				public String getColumnName() {
					return "Tested XSS parameters";
				}
				public Object getValue(Object key) {
					return "";//_model.getXSSTested((ConversationID) key);
				}
				public Class getColumnClass() {
					return String.class;
				}
		}); */
		// 2011-03-15 - JLS - Modifying rows showed in XSS panel - END
		TableSorter vts = new TableSorter(vtm, conversationTable.getTableHeader());
		TableSorter sts = new TableSorter(stm, suspectedTable.getTableHeader());
		
		conversationTable.setModel(vts);
		suspectedTable.setModel(sts);        
		
		ColumnWidthTracker.getTracker("ConversationTable").addTable(conversationTable);
		ColumnWidthTracker.getTracker("ConversationTable").addTable(suspectedTable);
		
		conversationTable.setDefaultRenderer(Date.class, new DateRenderer());
		suspectedTable.setDefaultRenderer(Date.class, new DateRenderer());

		// 2011-03-14 - JLS - Adding multi line support for Strings in the conversation table - BEGIN
		conversationTable.setDefaultRenderer(MultiLineString.class, new MultiLineCellRenderer());
		// 2011-03-14 - JLS - Adding multi line support for Strings in the conversation table - END

		_vulnerableUrlColumns = new ColumnDataModel[] { 
			new ColumnDataModel<HttpUrl>("Possible Injection ng", Boolean.class) {
				public Object getValue(final HttpUrl key) {
					return _model.isSuspected(key) ? Boolean.TRUE :  Boolean.FALSE;
				}
			}, 
			new ColumnDataModel<HttpUrl>("Injection-ng", Boolean.class) {
				public Object getValue(final HttpUrl key) {
					return _model.isXSSVulnerable(key)? Boolean.TRUE :  Boolean.FALSE;
				}
			}
		};
		java.awt.Dimension screenSize = java.awt.Toolkit.getDefaultToolkit().getScreenSize();
		editDialog.setBounds((screenSize.width-300)/2, (screenSize.height-150)/2, 450, 250);
		addTableListeners();
		createActions();
	}
	
	private void addTableListeners() {
		_showAction = new ShowConversationAction(_model.getVulnerableConversationModel());
		conversationTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
				public void valueChanged(ListSelectionEvent e) {
					if (e.getValueIsAdjusting()) return;
					int row = conversationTable.getSelectedRow();
					TableModel tm = conversationTable.getModel();
					if (row >-1) {
						ConversationID id = (ConversationID) tm.getValueAt(row, 0); // UGLY hack! FIXME!!!!
						_showAction.putValue("CONVERSATION", id);
					} else {
						_showAction.putValue("CONVERSATION", null);
					}
				}
		});
		
		conversationTable.addMouseListener(new MouseAdapter() {
				public void mouseClicked(MouseEvent e) {
					int row = conversationTable.rowAtPoint(e.getPoint());
					conversationTable.getSelectionModel().setSelectionInterval(row,row);
					if (e.getClickCount() == 2 && e.getButton() == MouseEvent.BUTTON1) {
						ActionEvent evt = new ActionEvent(conversationTable, 0, (String) _showAction.getValue(Action.ACTION_COMMAND_KEY));
						if (_showAction.isEnabled())
							_showAction.actionPerformed(evt);
					}
				}
		});
	}
	
	private void initComponents() {
		java.awt.GridBagConstraints gridBagConstraints;
		
		editDialog = new javax.swing.JDialog();
		tabbedPane = new javax.swing.JTabbedPane();
		jScrollPane4 = new javax.swing.JScrollPane();
		xssTextArea = new javax.swing.JTextArea();
		// 2011-07-05 - JLS - Adding a text area for the XSS url - BEGIN
		xssUrlFilter = new javax.swing.JTextArea();
		xssUrlFilterScrollPane = new javax.swing.JScrollPane();
		xssUrlFilterScrollPane.setViewportView(xssUrlFilter);
		tabbedPane.addTab("XSSng", jScrollPane4);
		// 2011-07-05 - JLS - Adding a text area for the XSS url - END
		jScrollPane3 = new javax.swing.JScrollPane();
		crlfTextArea = new javax.swing.JTextArea();
		jPanel3 = new javax.swing.JPanel();
		loadButton = new javax.swing.JButton();
		cancelButton = new javax.swing.JButton();
		okButton = new javax.swing.JButton();
		jSplitPane1 = new javax.swing.JSplitPane();
		jPanel1 = new javax.swing.JPanel();
		jLabel1 = new javax.swing.JLabel();
		jScrollPane1 = new javax.swing.JScrollPane();
		suspectedTable = new javax.swing.JTable();
		jPanel2 = new javax.swing.JPanel();
		jLabel2 = new javax.swing.JLabel();
		jScrollPane2 = new javax.swing.JScrollPane();
		conversationTable = new javax.swing.JTable();
		controlPanel = new javax.swing.JPanel();
		editButton = new javax.swing.JButton();
		checkButton = new javax.swing.JButton();
		activateButton = new javax.swing.JButton();

		// 2011-07-26 - JLS - Adding a button for SQLi tests - BEGIN
	 	activateSQLiTestsButton = new javax.swing.JButton();
	 	// 2011-07-26 - JLS - Adding a button for SQLi tests - BEGIN
	 	
		// 2011-03-14 - JLS - Adding a text area for the XSS search functions - BEGIN
		patternCompleteTextArea = new javax.swing.JTextArea();
		patternCompletejScrollPane = new javax.swing.JScrollPane();
		patternCompletejScrollPane.setViewportView(patternCompleteTextArea);
		patternPartialTextArea  = new javax.swing.JTextArea();
		patternPartialjScrollPane = new javax.swing.JScrollPane();
		patternPartialjScrollPane.setViewportView(patternPartialTextArea);
		tabbedPane.addTab("Pattern Complete to Find", patternCompletejScrollPane);
		tabbedPane.addTab("Pattern Partial to Find", patternPartialjScrollPane);
		// 2011-03-14 - JLS - Adding a text area for the XSS search functions - END
		
		editDialog.setTitle("Extensions");
		editDialog.setModal(true);
		tabbedPane.setMinimumSize(new java.awt.Dimension(200, 200));
		tabbedPane.setPreferredSize(new java.awt.Dimension(200, 200));
		jScrollPane4.setViewportView(xssTextArea);
		
		tabbedPane.addTab("XSSng", jScrollPane4);
		
		jScrollPane3.setViewportView(crlfTextArea);

		// 2011-07-05 - JLS - Adding a text area for the XSS url - BEGIN
		xssUrlFilterScrollPane.setViewportView(xssUrlFilter);
		tabbedPane.addTab("XSSng URL Filter", xssUrlFilterScrollPane);
		// 2011-07-05 - JLS - Adding a text area for the XSS url - END

		
		tabbedPane.addTab("CRLF Injection", jScrollPane3);
		
		editDialog.getContentPane().add(tabbedPane, java.awt.BorderLayout.CENTER);
		
		loadButton.setText("Load");
		loadButton.addActionListener(new java.awt.event.ActionListener() {
				public void actionPerformed(java.awt.event.ActionEvent evt) {
					loadButtonActionPerformed(evt);
				}
		});
		
		jPanel3.add(loadButton);
		
		cancelButton.setText("Cancel");
		cancelButton.addActionListener(new java.awt.event.ActionListener() {
				public void actionPerformed(java.awt.event.ActionEvent evt) {
					cancelButtonActionPerformed(evt);
				}
		});
		
		jPanel3.add(cancelButton);
		
		okButton.setText("Ok");
		okButton.addActionListener(new java.awt.event.ActionListener() {
				public void actionPerformed(java.awt.event.ActionEvent evt) {
					okButtonActionPerformed(evt);
				}
		});
		
		jPanel3.add(okButton);
		
		editDialog.getContentPane().add(jPanel3, java.awt.BorderLayout.SOUTH);
		
		setLayout(new java.awt.BorderLayout());
		
		jSplitPane1.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);
		jSplitPane1.setResizeWeight(0.5);
		jPanel1.setLayout(new java.awt.BorderLayout());
		
		jLabel1.setText("Tested Conversations");
		// 2011-07-29 - JLS - Adding a progress bar - BEGIN
		_progressBar = new JProgressBar(0, 100);
		_progressBar.setValue(100);
		_progressBar.setStringPainted(true);
		jPanel1.add(_progressBar, java.awt.BorderLayout.SOUTH);
		doUpdateProgressBarTimer.schedule(doUpdateProgressBarTimerTask, 5000, 1000);
		// 2011-07-29 - JLS - Adding a progress bar - END
		jPanel1.add(jLabel1, java.awt.BorderLayout.NORTH);
		
		suspectedTable.setModel(new javax.swing.table.DefaultTableModel(
			new Object [][] {
				{null, null, null, null},
				{null, null, null, null},
				{null, null, null, null},
				{null, null, null, null}
			},
			new String [] {
				"Title 1", "Title 2", "Title 3", "Title 4"
			}
			));
		suspectedTable.setAutoResizeMode(javax.swing.JTable.AUTO_RESIZE_OFF);
		jScrollPane1.setViewportView(suspectedTable);
		
		jPanel1.add(jScrollPane1, java.awt.BorderLayout.CENTER);
		
		jSplitPane1.setLeftComponent(jPanel1);
		
		jPanel2.setLayout(new java.awt.BorderLayout());
		
		jLabel2.setText("Confirmed Vulnerabilities");
		jPanel2.add(jLabel2, java.awt.BorderLayout.NORTH);
		
		conversationTable.setModel(new javax.swing.table.DefaultTableModel(
			new Object [][] {
				{null, null, null, null},
				{null, null, null, null},
				{null, null, null, null},
				{null, null, null, null}
			},
			new String [] {
				"Title 1", "Title 2", "Title 3", "Title 4"
			}
			));
		conversationTable.setAutoResizeMode(javax.swing.JTable.AUTO_RESIZE_OFF);
		jScrollPane2.setViewportView(conversationTable);
		
		jPanel2.add(jScrollPane2, java.awt.BorderLayout.CENTER);
		
		jSplitPane1.setRightComponent(jPanel2);
		
		add(jSplitPane1, java.awt.BorderLayout.CENTER);
		
		controlPanel.setLayout(new java.awt.GridBagLayout());
		
		editButton.setText("Edit Test Strings");
		editButton.addActionListener(new java.awt.event.ActionListener() {
				public void actionPerformed(java.awt.event.ActionEvent evt) {
					editButtonActionPerformed(evt);
				}
		});
		
		gridBagConstraints = new java.awt.GridBagConstraints();
		gridBagConstraints.gridwidth = 3;
		controlPanel.add(editButton, gridBagConstraints);
		
		checkButton.setText("Check");
		checkButton.addActionListener(new java.awt.event.ActionListener() {
				public void actionPerformed(java.awt.event.ActionEvent evt) {
					checkButtonActionPerformed(evt);
				}
		});
		
		controlPanel.add(checkButton, new java.awt.GridBagConstraints());

		if (! _xsscrlf.testAll()) {
			activateButton.setText("Activate");
		} else {
			activateButton.setText("Deactivate");
		}
		activateButton.addActionListener(new java.awt.event.ActionListener() {
				public void actionPerformed(java.awt.event.ActionEvent evt) {
					activateButtonActionPerformed(evt);
				}
		});
		
		controlPanel.add(activateButton, new java.awt.GridBagConstraints());

		
		// 2011-07-26 - JLS - Adding a button for SQLi tests - BEGIN
		if (! _xsscrlf.doSQLiTests()) {
			activateSQLiTestsButton.setText("Activate SQLi tests");
		} else {
			activateSQLiTestsButton.setText("Deactivate SQLi tests");
		}
		activateSQLiTestsButton.addActionListener(new java.awt.event.ActionListener() {
				public void actionPerformed(java.awt.event.ActionEvent evt) {
					activateSQLiTestsButtonActionPerformed(evt);
				}
		});
		
		controlPanel.add(activateSQLiTestsButton, new java.awt.GridBagConstraints());
		// 2011-07-26 - JLS - Adding a button for SQLi tests - END

		// 2011-03-14 - JLS - Adding a reAnalyse All button - BEGIN
		reAnalyseButton = new javax.swing.JButton();
		reAnalyseButton.setText("Re Analyse all conversations.");
		reAnalyseButton.addActionListener(new java.awt.event.ActionListener() {
				public void actionPerformed(java.awt.event.ActionEvent evt) {
					reAnalyseButtonActionPerformed(evt);
				}
		});
		
		controlPanel.add(reAnalyseButton, new java.awt.GridBagConstraints());
		// 2011-03-14 - JLS - Adding a reAnalyse All button - END

		// 2011-03-15 - JLS - Adding a reAnalyse All button - BEGIN
		reCheckButton = new javax.swing.JButton();
		reCheckButton.setText("Re CHECK all conversations (SOFT).");
		reCheckButton.addActionListener(new java.awt.event.ActionListener() {
				public void actionPerformed(java.awt.event.ActionEvent evt) {
					reCheckButtonActionPerformed(evt);
				}
		});
		
		controlPanel.add(reCheckButton, new java.awt.GridBagConstraints());
		// 2011-03-15 - JLS - Adding a reAnalyse All button - END
		
		add(controlPanel, java.awt.BorderLayout.SOUTH);
		
	}
	
	private void okButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_okButtonActionPerformed
		_model.setCRLFTestString(crlfTextArea.getText());
		_model.setXSSTestString(xssTextArea.getText());
		// 2011-07-05 - JLS - Adding a text area for the XSS url - BEGIN
		_xsscrlf.setUrlOfTarget(xssUrlFilter.getText());
		// 2011-07-05 - JLS - Adding a text area for the XSS url - END
		// 2011-03-14 - JLS - Adding a text area for the XSS search functions - BEGIN
		_xsscrlf.setXSSPatternToFind(patternCompleteTextArea.getText());
		_xsscrlf.setXSSPatternToFindPartial(patternPartialTextArea.getText());
		// 2011-03-14 - JLS - Adding a text area for the XSS search functions - END
		editDialog.setVisible(false);
	}//GEN-LAST:event_okButtonActionPerformed
	
	private void cancelButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cancelButtonActionPerformed
		editDialog.setVisible(false);
	}//GEN-LAST:event_cancelButtonActionPerformed
	
	private void loadButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_loadButtonActionPerformed
		JFileChooser jfc = new JFileChooser(Preferences.getPreference("XSSCRLF.DefaultDirectory"));
		jfc.setDialogTitle("Open test string file");
		int returnVal = jfc.showOpenDialog(this);
		if (returnVal == JFileChooser.APPROVE_OPTION) {
			File extFile = jfc.getSelectedFile();
			try {
				String testString=_xsscrlf.loadString(extFile);
				if (tabbedPane.getTitleAt(tabbedPane.getSelectedIndex()).equals("XSSng")) {
					xssTextArea.setText(testString);
				} else if (tabbedPane.getTitleAt(tabbedPane.getSelectedIndex()).equals("CRLF Injection")){
					crlfTextArea.setText(testString);
				}
			} catch (IOException ioe) {
				JOptionPane.showMessageDialog(null, new String[] {"Error loading test string: ", ioe.getMessage()}, "Error", JOptionPane.ERROR_MESSAGE);
			}
		}
		Preferences.setPreference("XSSCRLF.DefaultDirectory", jfc.getCurrentDirectory().getAbsolutePath());
	}//GEN-LAST:event_loadButtonActionPerformed
	
	private void editButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_editButtonActionPerformed
		xssTextArea.setText(_model.getXSSTestString());
		crlfTextArea.setText(_model.getCRLFTestString());
		// 2011-07-05 - JLS - Adding a text area for the XSS url - BEGIN
		xssUrlFilter.setText(_xsscrlf.getUrlOfTarget());
		// 2011-07-05 - JLS - Adding a text area for the XSS url - END
		patternCompleteTextArea.setText(_xsscrlf.getXSSPatternToFind());
		patternPartialTextArea.setText(_xsscrlf.getXSSPatternToFindPartial());
		editDialog.setVisible(true);
	}//GEN-LAST:event_editButtonActionPerformed
	
	private void checkButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_checkButtonActionPerformed
		
		String action = evt.getActionCommand();
		if (action.equals("Stop")) {
			_xsscrlf.stopChecks();
			return;
		}
		
		final int[] selection = suspectedTable.getSelectedRows();
		// XXX meder: selection in tables is buggy for now assume that all URLs were selected
		
		//      final int[] selection = new int[suspectedTable.getRowCount()];
		//      for(int k=0; k < selection.length; k++) selection[k]=k;
		
		if (selection == null || selection.length == 0) return;
		if (_xsscrlf.isBusy()) {
			showBusyMessage();
			return;
		}
		
		final ConversationID[] CIDs = new ConversationID[selection.length];
		TableModel tm = suspectedTable.getModel();
		
		for (int i=0; i<selection.length; i++) {
			CIDs[i]= (ConversationID) tm.getValueAt(i,0); // UGLY hack! FIXME!!!!            
		}
		
		checkButton.setText("Stop");
		new SwingWorker() {
			public Object construct() {                
				_xsscrlf.checkSelected(CIDs);
				return null;
				
			}
			public void finished() {
				Object result = getValue();
				if (result != null && result instanceof Throwable) {
					Throwable throwable = (Throwable) result;
					_logger.warning("Caught a : " + throwable.toString());
				}
				checkButton.setText("Check");
			}
		}.start();
	}//GEN-LAST:event_checkButtonActionPerformed


	private void activateButtonActionPerformed(java.awt.event.ActionEvent evt) {
		new SwingWorker() {
			public Object construct() {                
				_xsscrlf.activateSelected();
				if (! _xsscrlf.testAll()) {
					activateButton.setText("Activate");
				} else {
					activateButton.setText("Deactivate");
				}
				return null;
				
			}
			public void finished() {
				Object result = getValue();
				if (result != null && result instanceof Throwable) {
					Throwable throwable = (Throwable) result;
					_logger.warning("Caught a : " + throwable.toString());
				}
				//activateButton.setText("Activate");
			}
		}.start();
	}

	// 2011-07-26 - JLS - Adding a button for SQLi tests - BEGIN
	private void activateSQLiTestsButtonActionPerformed(java.awt.event.ActionEvent evt) {
		new SwingWorker() {
			public Object construct() {                
				;
				if (! _xsscrlf.switchSQLiTests()) {
					activateSQLiTestsButton.setText("Activate SQLi tests");
				} else {
					activateSQLiTestsButton.setText("Deactivate SQLi tests");
				}
				return null;
				
			}
			public void finished() {
				Object result = getValue();
				if (result != null && result instanceof Throwable) {
					Throwable throwable = (Throwable) result;
					_logger.warning("Caught a : " + throwable.toString());
				}
			}
		}.start();
	}
	// 2011-07-26 - JLS - Adding a button for SQLi tests - END
	
	
	
	// 2011-03-14 - JLS - Adding a reAnalyse All button - BEGIN
	private void reAnalyseButtonActionPerformed(java.awt.event.ActionEvent evt) {

		new SwingWorker() {
			public Object construct() {
				ConversationModel conversationModel = _model.getConversationModel();
				if (conversationModel == null) {
					_logger.severe("Unable to get the ConversationModel.");
					return null;
				}
				int count = conversationModel.getConversationCount();
				ConversationID id = null;
				reAnalyseButton.setEnabled(false);
				String oldButtonText = reAnalyseButton.getText() ;
				reAnalyseButton.setText ("RE Analysing conversations...");
				_logger.info ("Reanalysing all conversations with XSS-NG.");
				for (int i=0 ; i<count; i++) {
					id = conversationModel.getConversationAt(i);
					if (id != null) {
						_logger.finer("Analyzing again conversation: "+i);
						//_xsscrlf.responseReceived(conversationModel.getResponse(id), true);
						_xsscrlf.analyseForced(id, conversationModel.getRequest(id), conversationModel.getResponse(id), _xsscrlf.getPluginName(), Boolean.TRUE);
					} else {
						_logger.severe ("No id found for the Conversation : "+i);
					}
				}
				_logger.info ("Reanalysis finished.");
				reAnalyseButton.setText (oldButtonText);
				reAnalyseButton.setEnabled(true);
				return null;
			}
			public void finished() {
				Object result = getValue();
				if (result != null && result instanceof Throwable) {
					Throwable throwable = (Throwable) result;
					_logger.warning("Caught a : " + throwable.toString());
				}
			}
		}.start();
	}
	// 2011-03-14 - JLS - Adding a reAnalyse All button - END


	// 2011-03-15 - JLS - Adding a reCheck All button - BEGIN
	private void reCheckButtonActionPerformed(java.awt.event.ActionEvent evt) {
		// 2011-12-13 - JLS - Possibility to abort analysis - BEGIN
		if (! reCheckIsFinishedOrAborted) {
			reCheckIsFinishedOrAborted = Boolean.TRUE;
		} else {
			reCheckIsFinishedOrAborted = Boolean.FALSE;
			new SwingWorker() {
				public Object construct() {
					// 2011-12-13 - JLS - Adding a info about the number of conversations to analyze - BEGIN
					int numberOfConversationsAnalyzed = 0;
					// 2011-12-13 - JLS - Adding a info about the number of conversations to analyze - END
					
					ConversationModel conversationModel = _model.getConversationModel();
					if (conversationModel == null) {
						_logger.severe("Unable to get the ConversationModel.");
						return null;
					}
					int count = conversationModel.getConversationCount();
					ConversationID id = null;
					//reCheckButton.setEnabled(false);
					String oldButtonText = reCheckButton.getText() ;
					reCheckButton.setText ("RE Checking conversations...");
					_logger.info ("Rechecking conversations with XSS-NG.");
					for (int i=0 ; i<count; i++) {
						if (!reCheckIsFinishedOrAborted) {
							id = conversationModel.getConversationAt(i);
							if (id != null) {
								_logger.finer("Checking conversation: "+i);
								_xsscrlf.responseReceivedWithReanalyse(conversationModel.getResponse(id), true);
							} else {
								_logger.severe ("No id found for the Conversation : "+i);
							}
							numberOfConversationsAnalyzed++;
							reCheckButton.setText("Checking :" + numberOfConversationsAnalyzed + "/" + count);
						}
					}
					_logger.info ("Recheck finished.");
					reCheckButton.setText (oldButtonText);
					//reCheckButton.setEnabled(true);
					reCheckIsFinishedOrAborted = Boolean.TRUE;
					return null;
				}
				public void finished() {
					Object result = getValue();
					if (result != null && result instanceof Throwable) {
						Throwable throwable = (Throwable) result;
						_logger.warning("Caught a : " + throwable.toString());
					}
				}
			}.start();
		}
	}
	// 2011-03-15 - JLS - Adding a reCheck All button - END
	
	private void showBusyMessage() {
		_logger.warning("Plugin is still busy, please wait");
		// FIXME show a message dialog
	}
	
	public Action[] getConversationActions() {
		// JLS - 2010-07-21 - Adding actions
		return _conversationActions;
	}
	
	public ColumnDataModel[] getConversationColumns() {
		return _vulnerableConversationColumns;
	}
	
	public javax.swing.JPanel getPanel() {
		return this;
	}
	
	public String getPluginName() {
		return _xsscrlf.getPluginName();
	}
	
	public Action[] getUrlActions() {
		return null;
	}
	
	public ColumnDataModel[] getUrlColumns() {
		return _vulnerableUrlColumns;
	}

	// JLS - 2010-07-21 - Adding actions
	private void createActions() {
		_conversationActions = new Action[] {
			new XSSngTestConversation()
		};
	}
	
	
	// Variables declaration - do not modify//GEN-BEGIN:variables
	private javax.swing.JButton cancelButton;
	private javax.swing.JButton checkButton;
	private javax.swing.JButton activateButton;
	
	// 2011-07-26 - JLS - Adding a button for SQLi tests - BEGIN
	private javax.swing.JButton activateSQLiTestsButton = null;
	// 2011-07-26 - JLS - Adding a button for SQLi tests - BEGIN
	
	// 2011-03-14 - JLS - Adding a reAnalyse All button - BEGIN
	private javax.swing.JButton reAnalyseButton;
	// 2011-03-14 - JLS - Adding a reAnalyse All button - END

	// 2011-03-15 - JLS - Adding a reAnalyse All button - BEGIN
	private javax.swing.JButton reCheckButton;
	// 2011-03-15 - JLS - Adding a reAnalyse All button - END
	
	
	private javax.swing.JPanel controlPanel;
	private javax.swing.JTable conversationTable;
	private javax.swing.JTextArea crlfTextArea;
	private javax.swing.JButton editButton;
	private javax.swing.JDialog editDialog;
	private javax.swing.JLabel jLabel1;
	private javax.swing.JLabel jLabel2;
	private javax.swing.JPanel jPanel1;
	private javax.swing.JPanel jPanel2;
	private javax.swing.JPanel jPanel3;
	private javax.swing.JScrollPane jScrollPane1;
	private javax.swing.JScrollPane jScrollPane2;
	private javax.swing.JScrollPane jScrollPane3;
	private javax.swing.JScrollPane jScrollPane4;
	private javax.swing.JSplitPane jSplitPane1;
	private javax.swing.JButton loadButton;
	private javax.swing.JButton okButton;
	private javax.swing.JTable suspectedTable;
	private javax.swing.JTabbedPane tabbedPane;
	private javax.swing.JTextArea xssTextArea;
	// 2011-07-05 - JLS - Adding a text area for the XSS url - BEGIN
	private javax.swing.JTextArea xssUrlFilter = null;
	private javax.swing.JScrollPane xssUrlFilterScrollPane = null;
	// 2011-07-05 - JLS - Adding a text area for the XSS url - END
	// End of variables declaration//GEN-END:variables
	// 2011-03-14 - JLS - Adding a text area for the XSS search functions - BEGIN
	private javax.swing.JScrollPane patternCompletejScrollPane = null;
	private javax.swing.JScrollPane patternPartialjScrollPane = null;
	private javax.swing.JTextArea patternCompleteTextArea = null;
	private javax.swing.JTextArea patternPartialTextArea = null;
	// JLS 2010-07-21 - Adding actions
	private class XSSngTestConversation extends AbstractAction {
		private static final long serialVersionUID = -5862303750434463107L;
		/** Creates a new instance of ShowConversationAction */
		public XSSngTestConversation() {
			putValue(NAME, "Send to XSS ng");
			putValue(SHORT_DESCRIPTION, "Loads this request into the XSS ng plugin");
			putValue("CONVERSATION", null);
		}
		
		public void actionPerformed(ActionEvent e) {
			Object o = getValue("CONVERSATION");
			if (o == null || ! (o instanceof ConversationID)) return;
			
			// 2011-07-07 - JLS - Modifying order of calls - BEGIN
			_xsscrlf.checkSelected((ConversationID) o);
			// 2011-07-07 - JLS - Modifying order of calls - END
		}
		
		public void putValue(String key, Object value) {
			super.putValue(key, value);
			if (key != null && key.equals("CONVERSATION")) {
				if (value != null && value instanceof ConversationID) {
					setEnabled(true);
				} else {
					setEnabled(false);
				}
			}
		}
		
	}
	
}
