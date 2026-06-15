#!/usr/bin/env python
# -*- coding: utf-8 -*- 

from javax.swing import BoxLayout
from java.awt import Dimension
from burp import IInterceptedProxyMessage

def _get_viewer_width(extender, visible_count):
        fallback_width = 1200
        try:
                viewport_width = extender.requests_scrollpane.getViewport().getExtentSize().width
        except:
                viewport_width = fallback_width

        if viewport_width <= 0:
                viewport_width = fallback_width

        if visible_count <= 1:
                return viewport_width
        return max(int(viewport_width / 3), 360)

def _set_viewer_size(extender, comp, visible_count):
        width = _get_viewer_width(extender, visible_count)
        try:
                viewport_height = extender.requests_scrollpane.getViewport().getExtentSize().height
        except:
                viewport_height = 500

        if viewport_height <= 0:
                viewport_height = 500

        comp.setPreferredSize(Dimension(width, viewport_height))
        comp.setMinimumSize(Dimension(300, 1))
        comp.setMaximumSize(Dimension(width, 2147483647))

def addFilterHelper(typeObj, model, textObj):
        typeName = typeObj.getSelectedItem().split(":")[0]
        model.addElement(typeName + ": " + textObj.getText().strip())
        textObj.setText("")

def delFilterHelper(listObj):
        index = listObj.getSelectedIndex()
        if not index == -1:
                listObj.getModel().remove(index)

def modFilterHelper(listObj, typeObj, textObj):
        index = listObj.getSelectedIndex()
        if not index == -1:
                valt = listObj.getSelectedValue()
                val = valt.split(":", 1)[1].strip()
                modifiedFilter = valt.split(":", 1)[0].strip() + ":"
                typeObj.getModel().setSelectedItem(modifiedFilter)
                if ("Scope items" not in valt) and ("Content-Len" not in valt):
                        textObj.setText(val)
                listObj.getModel().remove(index)

def expand(extender, comp):
        comp.setTitleAt(2, "Collapse")
        extender.requests_panel.removeAll()
        extender.requests_panel.setLayout(BoxLayout(extender.requests_panel, BoxLayout.X_AXIS))
        _set_viewer_size(extender, comp, 1)
        extender.requests_panel.add(comp)
        extender.requests_panel.revalidate()
        extender.requests_panel.repaint()
        if hasattr(extender, 'requests_scrollpane'):
                extender.requests_scrollpane.revalidate()
                extender.requests_scrollpane.repaint()
        extender.expanded_requests = 1

def collapse(extender, comp):
        comp.setTitleAt(2, "Expand")
        rebuildViewerPanel(extender)

def rebuildViewerPanel(extender):
        all_viewer_tabs = []
        if hasattr(extender, 'original_requests_tabs'):
                all_viewer_tabs.append(extender.original_requests_tabs)
        if hasattr(extender, 'unauthenticated_requests_tabs'):
                all_viewer_tabs.append(extender.unauthenticated_requests_tabs)
        if hasattr(extender, 'user_viewers'):
                all_viewer_tabs.extend([v['tabs'] for v in extender.user_viewers.values()])
        for tabs in all_viewer_tabs:
                if tabs.getTabCount() > 2:
                        tabs.setTitleAt(2, "Expand")

        extender.requests_panel.removeAll()
        viewer_components = []

        if extender.viewer_visibility.get('original', True):
                viewer_components.append(extender.original_requests_tabs)

        if extender.viewer_visibility.get('unauthenticated', True):
                viewer_components.append(extender.unauthenticated_requests_tabs)

        if hasattr(extender, 'user_viewers'):
                for user_id in sorted(extender.user_viewers.keys()):
                        key = 'user_{}'.format(user_id)
                        if extender.viewer_visibility.get(key, True):
                                viewer_components.append(extender.user_viewers[user_id]['tabs'])

        extender.requests_panel.setLayout(BoxLayout(extender.requests_panel, BoxLayout.X_AXIS))

        visible_count = len(viewer_components)
        for comp in viewer_components:
                _set_viewer_size(extender, comp, visible_count)
                extender.requests_panel.add(comp)

        extender.requests_panel.revalidate()
        extender.requests_panel.repaint()
        if hasattr(extender, 'requests_scrollpane'):
                extender.requests_scrollpane.revalidate()
                extender.requests_scrollpane.repaint()
        extender.expanded_requests = 0

def handle_proxy_message(self,message):
        currentPort = message.getListenerInterface().split(":")[1]
        for i in range(0, self.IFList.getModel().getSize()):
            interceptionFilter = self.IFList.getModel().getElementAt(i)
            interceptionFilterTitle = interceptionFilter.split(":")[0]
            if interceptionFilterTitle == "Drop proxy listener ports":
                portsList = interceptionFilter[27:].split(",")
                portsList = [int(i) for i in portsList]
                if int(currentPort) in portsList:
                    message.setInterceptAction(IInterceptedProxyMessage.ACTION_DROP)
