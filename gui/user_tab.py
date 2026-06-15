#!/usr/bin/env python
# -*- coding: utf-8 -*- 

from javax.swing import JPanel
from javax.swing import JLabel
from javax.swing import JButton
from javax.swing import JTabbedPane
from javax.swing import JOptionPane
from javax.swing import JTextArea
from javax.swing import JScrollPane
from javax.swing import GroupLayout
from javax.swing import JSplitPane
from javax.swing import JTable
from javax.swing.border import LineBorder
from javax.swing.table import AbstractTableModel
from javax.swing.table import DefaultTableCellRenderer
from javax.swing.event import ListSelectionListener
from javax.swing.event import DocumentListener
from java.awt import BorderLayout
from java.awt import FlowLayout
from java.awt import Color
from java.awt import Font
from java.awt import Dimension
from java.awt.event import ActionListener
import base64
import json
import re

from gui.enforcement_detector import EnforcementDetectors
from gui.match_replace import MatchReplace

USER_COLORS = [
    Color(244, 67, 54),
    Color(33, 150, 243),
    Color(76, 175, 80),
    Color(255, 193, 7),
    Color(156, 39, 176),
    Color(0, 188, 212),
    Color(255, 112, 67),
    Color(121, 85, 72),
    Color(63, 81, 181),
    Color(139, 195, 74),
    Color(233, 30, 99),
    Color(0, 150, 136),
    Color(96, 125, 139),
    Color(205, 220, 57),
    Color(103, 58, 183)
]

def get_user_color(user_id):
    return USER_COLORS[(user_id - 1) % len(USER_COLORS)]

def _safe_json_loads(text):
    try:
        return json.loads(text)
    except:
        return None

def _decode_base64url(value):
    try:
        padded = value + ("=" * ((4 - len(value) % 4) % 4))
        return base64.urlsafe_b64decode(padded)
    except:
        return None

def decode_jwt(token):
    parts = token.strip().split(".")
    if len(parts) < 2:
        return None

    header = _safe_json_loads(_decode_base64url(parts[0]))
    payload = _safe_json_loads(_decode_base64url(parts[1]))
    if not isinstance(payload, dict):
        return None

    identity_keys = ["sub", "email", "preferred_username", "username", "name", "client_id"]
    identity = ""
    for key in identity_keys:
        if key in payload:
            identity = "{}={}".format(key, payload[key])
            break

    claims = []
    for key in ["iss", "aud", "scope", "scp", "roles", "role"]:
        if key in payload:
            value = payload[key]
            if isinstance(value, list):
                value = ",".join([str(v) for v in value])
            claims.append("{}={}".format(key, value))

    alg = ""
    if isinstance(header, dict) and "alg" in header:
        alg = "alg={}".format(header["alg"])

    preview_parts = []
    if alg:
        preview_parts.append(alg)
    if identity:
        preview_parts.append(identity)
    preview_parts.extend(claims[:3])

    return {
        "identity": identity,
        "preview": "; ".join(preview_parts) if preview_parts else "JWT payload decoded"
    }

def summarize_header_text(header_text):
    auth_type = "Custom headers"
    identifier = ""
    decoded_preview = ""
    header_preview = " ".join(header_text.split())

    jwt_match = re.search(r'Authorization:\s*Bearer\s+([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)', header_text, re.I)
    if jwt_match:
        auth_type = "Bearer JWT"
        decoded = decode_jwt(jwt_match.group(1))
        if decoded:
            identifier = decoded["identity"]
            decoded_preview = decoded["preview"]
        else:
            decoded_preview = "JWT-like bearer token, but payload could not be decoded"
    elif re.search(r'Authorization:', header_text, re.I):
        auth_type = "Authorization header"
        auth_line = re.search(r'Authorization:\s*([^\r\n]+)', header_text, re.I)
        if auth_line:
            identifier = auth_line.group(1).split()[0]
    elif re.search(r'Cookie:', header_text, re.I):
        auth_type = "Cookie"
        cookie_line = re.search(r'Cookie:\s*([^\r\n]+)', header_text, re.I)
        if cookie_line:
            cookie_names = []
            jwt_previews = []
            for cookie in cookie_line.group(1).split(";"):
                if "=" in cookie:
                    name, value = cookie.strip().split("=", 1)
                    cookie_names.append(name)
                    decoded = decode_jwt(value)
                    if decoded:
                        jwt_previews.append("{}: {}".format(name, decoded["preview"]))
            identifier = ", ".join(cookie_names[:5])
            if len(cookie_names) > 5:
                identifier += "..."
            decoded_preview = "; ".join(jwt_previews) if jwt_previews else "Opaque/encrypted cookie values"

    return {
        "auth_type": auth_type,
        "identifier": identifier,
        "decoded_preview": decoded_preview,
        "header_preview": header_preview[:180]
    }

class UserSummaryTableModel(AbstractTableModel):
    COLUMNS = ["", "User", "Auth Type", "Identifier", "Decoded Preview", "Header Preview"]

    def __init__(self, user_tab):
        self.user_tab = user_tab

    def getColumnCount(self):
        return len(self.COLUMNS)

    def getRowCount(self):
        return len(self.user_tab.get_ordered_user_ids())

    def getColumnName(self, column):
        return self.COLUMNS[column]

    def getValueAt(self, row, column):
        user_id = self.user_tab.get_user_id_at_row(row)
        if user_id is None:
            return ""

        user_data = self.user_tab.user_tabs[user_id]
        summary = summarize_header_text(user_data['headers_instance'].replaceString.getText())

        if column == 0:
            return " "
        if column == 1:
            return user_data['user_name']
        if column == 2:
            return summary["auth_type"]
        if column == 3:
            return summary["identifier"]
        if column == 4:
            return summary["decoded_preview"]
        if column == 5:
            return summary["header_preview"]
        return ""

class UserSummaryRenderer(DefaultTableCellRenderer):
    def __init__(self, user_tab):
        DefaultTableCellRenderer.__init__(self)
        self.user_tab = user_tab

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        comp = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column)
        model_row = table.convertRowIndexToModel(row)
        user_id = self.user_tab.get_user_id_at_row(model_row)
        if column == 0 and user_id is not None:
            comp.setBackground(get_user_color(user_id))
            comp.setForeground(get_user_color(user_id))
            return comp
        if isSelected:
            comp.setBackground(table.getSelectionBackground())
            comp.setForeground(table.getSelectionForeground())
        else:
            comp.setBackground(Color.WHITE)
            comp.setForeground(Color.BLACK)
        return comp

class UserSummarySelectionListener(ListSelectionListener):
    def __init__(self, user_tab):
        self.user_tab = user_tab

    def valueChanged(self, event):
        if not event.getValueIsAdjusting():
            self.user_tab.show_selected_user_from_table()

class HeaderDocumentListener(DocumentListener):
    def __init__(self, user_tab):
        self.user_tab = user_tab

    def insertUpdate(self, event):
        self.user_tab.refresh_user_summary()

    def removeUpdate(self, event):
        self.user_tab.refresh_user_summary()

    def changedUpdate(self, event):
        self.user_tab.refresh_user_summary()

class UserHeaders():
    DEFUALT_REPLACE_TEXT = "Cookie: Insert=injected; cookie=or;\nHeader: here"

    def __init__(self, user_id, extender, user_tab=None):
        self.user_id = user_id
        self._extender = extender
        self.user_tab = user_tab

    def draw(self):
        self.headersPnl = JPanel()
        layout = GroupLayout(self.headersPnl)
        self.headersPnl.setLayout(layout)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)

        self.replaceString = JTextArea(self.DEFUALT_REPLACE_TEXT, 5, 30)
        self.replaceString.setWrapStyleWord(True)
        self.replaceString.setLineWrap(True)
        if self.user_tab:
            self.replaceString.getDocument().addDocumentListener(HeaderDocumentListener(self.user_tab))

        self.scrollReplaceString = JScrollPane(self.replaceString)
        self.scrollReplaceString.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED)
        self.scrollReplaceString.setBorder(LineBorder(Color.BLACK))

        self.fromLastRequestLabel = JLabel("From last request:")

        self.fetchCookiesHeaderButton = JButton("Fetch Cookies header",
                                actionPerformed=self.fetchCookiesHeader)
        self.fetchCookiesHeaderButton.setEnabled(False)

        self.fetchAuthorizationHeaderButton = JButton("Fetch Authorization header",
                                actionPerformed=self.fetchAuthorizationHeader)
        self.fetchAuthorizationHeaderButton.setEnabled(False)

        layout.setHorizontalGroup(
            layout.createParallelGroup()
                .addComponent(self.scrollReplaceString,
                    GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, 2147483647)
                .addComponent(self.fromLastRequestLabel)
                .addGroup(layout.createSequentialGroup()
                    .addComponent(self.fetchCookiesHeaderButton)
                    .addComponent(self.fetchAuthorizationHeaderButton)
                )
        )

        layout.setVerticalGroup(
            layout.createSequentialGroup()
                .addComponent(self.scrollReplaceString,
                    GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.fromLastRequestLabel)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self.fetchCookiesHeaderButton)
                    .addComponent(self.fetchAuthorizationHeaderButton)
                )
        )

    def fetchCookiesHeader(self, event):
        if self._extender.lastCookiesHeader:
            self.replaceString.setText(self._extender.lastCookiesHeader)

    def fetchAuthorizationHeader(self, event):
        if self._extender.lastAuthorizationHeader:
            self.replaceString.setText(self._extender.lastAuthorizationHeader)


class UserTab():
    def __init__(self, extender):
        self._extender = extender
        self.user_count = 0
        self.user_tabs = {}
        self.user_names = []

    def draw(self):
        self._extender.userPanel = JPanel(BorderLayout())
        
        buttonPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        
        self.addUserBtn = JButton("Add User")
        self.addUserBtn.addActionListener(AddUserAction(self))
        buttonPanel.add(self.addUserBtn)
        
        self.removeUserBtn = JButton("Remove User")
        self.removeUserBtn.addActionListener(RemoveUserAction(self))
        buttonPanel.add(self.removeUserBtn)
        
        self.duplicateUserBtn = JButton("Duplicate User")
        self.duplicateUserBtn.addActionListener(DuplicateUserAction(self))
        buttonPanel.add(self.duplicateUserBtn)
        
        self.renameUserBtn = JButton("Rename User")
        self.renameUserBtn.addActionListener(RenameUserAction(self))
        buttonPanel.add(self.renameUserBtn)
        
        self.userSummaryModel = UserSummaryTableModel(self)
        self.userSummaryTable = JTable(self.userSummaryModel)
        self.userSummaryTable.setDefaultRenderer(self.userSummaryTable.getColumnClass(0), UserSummaryRenderer(self))
        self.userSummaryTable.setRowSelectionAllowed(True)
        self.userSummaryTable.setSelectionMode(0)
        self.userSummaryTable.getSelectionModel().addListSelectionListener(UserSummarySelectionListener(self))
        self.userSummaryTable.getColumnModel().getColumn(0).setPreferredWidth(28)
        self.userSummaryTable.getColumnModel().getColumn(0).setMaxWidth(32)
        self.userSummaryTable.getColumnModel().getColumn(1).setPreferredWidth(120)
        self.userSummaryTable.getColumnModel().getColumn(2).setPreferredWidth(130)
        self.userSummaryTable.getColumnModel().getColumn(3).setPreferredWidth(180)
        self.userSummaryTable.getColumnModel().getColumn(4).setPreferredWidth(360)
        self.userSummaryTable.getColumnModel().getColumn(5).setPreferredWidth(420)
        self.userSummaryScrollPane = JScrollPane(self.userSummaryTable)
        self.userSummaryScrollPane.setMinimumSize(Dimension(1, 80))

        self.userDetailPanel = JPanel(BorderLayout())
        self.userDetailPanel.setMinimumSize(Dimension(1, 120))

        self.userSplitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self.userSplitPane.setResizeWeight(0.35)
        self.userSplitPane.setTopComponent(self.userSummaryScrollPane)
        self.userSplitPane.setBottomComponent(self.userDetailPanel)

        self.userTabs = JTabbedPane()
        
        self.add_user()
        
        self._extender.userPanel.add(buttonPanel, BorderLayout.NORTH)
        self._extender.userPanel.add(self.userSplitPane, BorderLayout.CENTER)
    
    def add_user(self):
        self.user_count += 1
        user_name = "User {}".format(self.user_count)
        unique_user_name = self.get_unique_name(user_name)

        self.user_names.append(unique_user_name)

        userPanel = JPanel(BorderLayout())
        
        headerPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        headerLabel = JLabel(unique_user_name)
        headerLabel.setFont(Font("Tahoma", Font.BOLD, 12))
        headerPanel.add(headerLabel)
        
        userSubTabs = JTabbedPane()
        
        user_headers = UserHeaders(self.user_count, self._extender, self)
        user_headers.draw()

        if self._extender.lastCookiesHeader:
            user_headers.fetchCookiesHeaderButton.setEnabled(True)
        if self._extender.lastAuthorizationHeader:
            user_headers.fetchAuthorizationHeaderButton.setEnabled(True)

        user_ed = UserEnforcementDetector(self.user_count)
        user_ed.draw()
        
        user_mr = UserMatchReplace(self.user_count)
        user_mr.draw()
        
        userSubTabs.addTab("Headers", user_headers.headersPnl)
        userSubTabs.addTab("Enforcement Detector", user_ed.EDPnl)
        userSubTabs.addTab("Match/Replace", user_mr.MRPnl)
        
        userPanel.add(headerPanel, BorderLayout.NORTH)
        userPanel.add(userSubTabs, BorderLayout.CENTER)
        
        self.user_tabs[self.user_count] = {
            'user_id': self.user_count,
            'user_name': unique_user_name,
            'panel': userPanel,
            'subtabs': userSubTabs,
            'headers_instance': user_headers,
            'ed_instance': user_ed,
            'mr_instance': user_mr,
            'header_label': headerLabel
        }
        
        self.userTabs.addTab(unique_user_name, userPanel)
        
        self.userTabs.setSelectedIndex(self.userTabs.getTabCount() - 1)
        self.refresh_user_summary()
        self.select_user_by_id(self.user_count)

        if hasattr(self._extender, 'tabs_instance') and self._extender.tabs_instance:
            self._extender.tabs_instance.createUserViewerTabs(self.user_count, unique_user_name)
            from helpers.filters import rebuildViewerPanel
            rebuildViewerPanel(self._extender)

        self.refreshTableStructure()

    def remove_user(self):
        if self.userTabs.getTabCount() <= 1:
            JOptionPane.showMessageDialog(None, "Cannot remove the last user!", "Warning", JOptionPane.WARNING_MESSAGE)
            return
        
        selected_index = self.userTabs.getSelectedIndex()

        if selected_index >= 0:
            selected_panel = self.userTabs.getComponentAt(selected_index)

            user_id_to_remove = None
            user_name_to_remove = None

            for user_id, user_data in self.user_tabs.items():
                if user_data['panel'] == selected_panel:
                    user_id_to_remove = user_id
                    user_name_to_remove = user_data['user_name']
                    break

            if user_id_to_remove and user_name_to_remove:
                if user_name_to_remove in self.user_names:
                    self.user_names.remove(user_name_to_remove)

                del self.user_tabs[user_id_to_remove]

                self.userTabs.removeTabAt(selected_index)
                self.refresh_user_summary()
                next_index = min(selected_index, self.userTabs.getTabCount() - 1)
                if next_index >= 0:
                    self.userTabs.setSelectedIndex(next_index)
                    self.select_user_by_id(self.get_user_id_at_row(next_index))
                else:
                    self.userDetailPanel.removeAll()
                    self.userDetailPanel.revalidate()
                    self.userDetailPanel.repaint()

                if hasattr(self._extender, 'tabs_instance') and self._extender.tabs_instance:
                    self._extender.tabs_instance.removeUserViewerTabs(user_id_to_remove)

                self.refreshTableStructure()

    def reset_user(self):
        self.userTabs.removeAll()
        self.user_tabs.clear()
        del self.user_names[:]
        self.user_count = 0
        if hasattr(self, 'userDetailPanel'):
            self.userDetailPanel.removeAll()

        if hasattr(self._extender, 'user_viewers'):
            self._extender.user_viewers.clear()
            keys_to_remove = [k for k in self._extender.viewer_visibility if k.startswith('user_')]
            for k in keys_to_remove:
                del self._extender.viewer_visibility[k]

        self.add_user()
        self.refresh_user_summary()
        
    def duplicate_user(self):
        selected_index = self.userTabs.getSelectedIndex()

        if selected_index >= 0:
            selected_panel = self.userTabs.getComponentAt(selected_index)
            source_user_data = None
            
            for user_id, user_data in self.user_tabs.items():
                if user_data['panel'] == selected_panel:
                    source_user_data = user_data
                    break
            
            if source_user_data:
                self.add_user()
                new_user_id = self.user_count
                new_user_data = self.user_tabs[new_user_id]

                self.copy_headers_settings(source_user_data['headers_instance'], new_user_data['headers_instance'])
                self.copy_ed_settings(source_user_data['ed_instance'], new_user_data['ed_instance'])
                self.copy_mr_settings(source_user_data['mr_instance'], new_user_data['mr_instance'])
    
    def copy_ed_settings(self, source_ed, target_ed):
        target_ed.EDModel.clear()
        for i in range(source_ed.EDModel.getSize()):
            target_ed.EDModel.addElement(source_ed.EDModel.getElementAt(i))
        
        target_ed.EDType.setSelectedIndex(source_ed.EDType.getSelectedIndex())
        target_ed.EDText.setText(source_ed.EDText.getText())
        target_ed.AndOrType.setSelectedIndex(source_ed.AndOrType.getSelectedIndex())

    def copy_headers_settings(self, source_headers, target_headers):
        target_headers.replaceString.setText(source_headers.replaceString.getText())

    def copy_mr_settings(self, source_mr, target_mr):
        target_mr.MRModel.clear()
        for i in range(source_mr.MRModel.getSize()):
            target_mr.MRModel.addElement(source_mr.MRModel.getElementAt(i))
        
        target_mr.MRType.setSelectedIndex(source_mr.MRType.getSelectedIndex())
        target_mr.MText.setText(source_mr.MText.getText())
        target_mr.RText.setText(source_mr.RText.getText())
        
        target_mr.badProgrammerMRModel.clear()
        for key, value in source_mr.badProgrammerMRModel.items():
            if hasattr(value, 'copy'):
                target_mr.badProgrammerMRModel[key] = value.copy()
            elif isinstance(value, dict):
                target_mr.badProgrammerMRModel[key] = dict(value)
            else:
                target_mr.badProgrammerMRModel[key] = value
                            
    def rename_user(self):
        selected_index = self.userTabs.getSelectedIndex()

        if selected_index >= 0:
            current_name = self.userTabs.getTitleAt(selected_index)
            new_name = JOptionPane.showInputDialog(None, "Enter new name for user:", "Rename User", JOptionPane.QUESTION_MESSAGE, None, None, current_name)
            
            if new_name and new_name.strip():
                if current_name in self.user_names:
                    self.user_names.remove(current_name)

                unique_name = self.get_unique_name(new_name.strip())
                self.user_names.append(unique_name)

                self.userTabs.setTitleAt(selected_index, unique_name)

                selected_panel = self.userTabs.getComponentAt(selected_index)

                for user_id, user_data in self.user_tabs.items():
                    if user_data['panel'] == selected_panel:
                        user_data['header_label'].setText(unique_name)
                        user_data['user_name'] = unique_name
                        if hasattr(self._extender, 'tabs_instance') and self._extender.tabs_instance:
                            self._extender.tabs_instance.renameUserViewerTabs(user_id, unique_name)
                        break

                self.refresh_user_summary()
                self.refreshTableStructure()

    def get_unique_name(self, name):
        if name not in self.user_names:
            return name
        
        counter = 1
        while True:
            candidate_name = "{} Copy".format(name) if counter == 1 else "{} Copy {}".format(name, counter)
            
            if candidate_name not in self.user_names:
                return candidate_name
            
            counter += 1
            
            if counter > 100:
                return "{} Copy {}".format(name, counter)
    
    def refreshTableStructure(self):
        if hasattr(self._extender, 'tableModel'):
            self._extender.tableModel.fireTableStructureChanged()
        if hasattr(self._extender, 'logTable'):
            self._extender.logTable.updateColumnWidths()

    def get_ordered_user_ids(self):
        return sorted(self.user_tabs.keys())

    def get_user_id_at_row(self, row):
        user_ids = self.get_ordered_user_ids()
        if row is not None and row >= 0 and row < len(user_ids):
            return user_ids[row]
        return None

    def get_row_for_user_id(self, user_id):
        user_ids = self.get_ordered_user_ids()
        if user_id in user_ids:
            return user_ids.index(user_id)
        return -1

    def refresh_user_summary(self):
        if hasattr(self, 'userSummaryModel'):
            self.userSummaryModel.fireTableDataChanged()

    def select_user_by_id(self, user_id):
        row = self.get_row_for_user_id(user_id)
        if row >= 0 and hasattr(self, 'userSummaryTable'):
            self.userSummaryTable.setRowSelectionInterval(row, row)
            self.show_user_detail(user_id)

    def show_selected_user_from_table(self):
        if not hasattr(self, 'userSummaryTable'):
            return
        selected = self.userSummaryTable.getSelectedRow()
        if selected < 0:
            return
        model_row = self.userSummaryTable.convertRowIndexToModel(selected)
        user_id = self.get_user_id_at_row(model_row)
        if user_id is not None:
            self.show_user_detail(user_id)

    def show_user_detail(self, user_id):
        if user_id not in self.user_tabs:
            return

        user_data = self.user_tabs[user_id]
        self.userDetailPanel.removeAll()
        self.userDetailPanel.add(user_data['panel'], BorderLayout.CENTER)
        self.userDetailPanel.revalidate()
        self.userDetailPanel.repaint()

        index = self.userTabs.indexOfComponent(user_data['panel'])
        if index >= 0:
            self.userTabs.setSelectedIndex(index)
            
class UserEnforcementDetector(EnforcementDetectors):

    def __init__(self, user_id):
        self.isolated_extender = type('IsolatedExtender', (object,), {})()
        self.user_id = user_id
        
        EnforcementDetectors.__init__(self, self.isolated_extender)

    def draw(self):
        EnforcementDetectors.draw(self)
        self.EDPnl = self.isolated_extender.EDPnl
        self.EDType = self.isolated_extender.EDType
        self.EDText = self.isolated_extender.EDText
        self.EDModel = self.isolated_extender.EDModel
        self.EDList = self.isolated_extender.EDList
        self.AndOrType = self.isolated_extender.AndOrType

class UserMatchReplace(MatchReplace):
    def __init__(self, user_id):
        self.isolated_extender = type('IsolatedExtender', (object,), {})()
        self.user_id = user_id
        
        MatchReplace.__init__(self, self.isolated_extender)

    def draw(self):
        MatchReplace.draw(self)

        self.MRPnl = self.isolated_extender.MRPnl
        self.MRType = self.isolated_extender.MRType
        self.MText = self.isolated_extender.MText
        self.RText = self.isolated_extender.RText
        self.MRModel = self.isolated_extender.MRModel
        self.MRList = self.isolated_extender.MRList
        self.badProgrammerMRModel = self.isolated_extender.badProgrammerMRModel

class AddUserAction(ActionListener):
    def __init__(self, user_tab):
        self.user_tab = user_tab
    
    def actionPerformed(self, event):
        self.user_tab.add_user()

class RemoveUserAction(ActionListener):
    def __init__(self, user_tab):
        self.user_tab = user_tab
    
    def actionPerformed(self, event):
        self.user_tab.remove_user()

class DuplicateUserAction(ActionListener):
    def __init__(self, user_tab):
        self.user_tab = user_tab
    
    def actionPerformed(self, event):
        self.user_tab.duplicate_user()

class RenameUserAction(ActionListener):
    def __init__(self, user_tab):
        self.user_tab = user_tab
    
    def actionPerformed(self, event):
        self.user_tab.rename_user()
