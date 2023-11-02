from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
from burp import ITab
from javax.swing import JList, DefaultListModel, JScrollPane, JPanel, JButton, BoxLayout, JTextField
from java.awt import BorderLayout, Container, Dimension
from java.nio import ByteBuffer
import time
import array

import re

class BurpExtender(IBurpExtender, IHttpListener, IProxyListener, ITab):
    cookies = set()

    def registerExtenderCallbacks(self, callbacks):
        self.debug = False
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName("Cookie Capture")
        self.cookie_states = {}  # Dictionary to store the state of each cookie
        
        # Create the main GUI
        self.panel = JPanel()
        self.panel.setLayout(BorderLayout(10, 10))
        
        # Create a search field
        search_panel = JPanel()
        self.search_field = JTextField(20, actionPerformed=self.search_cookies)
        search_panel.add(self.search_field)
        self.panel.add(search_panel, BorderLayout.PAGE_START)
        
        # Main Cookie panel
        self.cookie_list = DefaultListModel()
        self.cookie_jlist = JList(self.cookie_list)
        self.cookie_scroll = JScrollPane(self.cookie_jlist)
        self.panel.add(self.cookie_scroll, BorderLayout.CENTER)
        
        self.enable_button = JButton("Enable Selected", actionPerformed=self.enable_selected)
        self.disable_button = JButton("Disable Selected", actionPerformed=self.disable_selected)
        
        button_panel = JPanel()
        button_panel.add(self.enable_button)
        button_panel.add(self.disable_button)
        self.panel.add(button_panel, BorderLayout.PAGE_END)
        
        callbacks.customizeUiComponent(self.panel)
        
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)        
        callbacks.registerProxyListener(self)

    def processProxyMessage(self, messageIsRequest, message):
        if messageIsRequest:
            # Modify the request here as needed
            modified_request = self.modify_request(message.getMessageInfo(), message.getMessageInfo().getRequest())
            if(not modified_request):
                return
            
            # Create a new request with the modifications
            http_service = message.getMessageInfo().getHttpService()
            modified_request_response = self.callbacks.makeHttpRequest(http_service, modified_request)

            # Update the history entry with "Auto-modified request"
            message.getMessageInfo().setRequest(modified_request_response.getRequest())

    # Implement the modify_request method to customize the request modifications
    def modify_request(self, messageInfo, original_request):
        requestInfo = self.helpers.analyzeRequest(original_request)
        headers = requestInfo.getHeaders()
        bodyOffset = requestInfo.getBodyOffset()

        requestString = self.helpers.bytesToString(original_request)
        requestBody = requestString[bodyOffset:]

        updatedRequest = self.removeCookies(headers, requestBody, messageInfo)

        # Your modification logic here
        return updatedRequest
    
    # Grab any new cookies and store them to allow them to be toggled
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest or not toolFlag == self.callbacks.TOOL_PROXY:
            return
            
        requestInfo = self.helpers.analyzeRequest(messageInfo)
        headers = requestInfo.getHeaders()
        tmpCookies = self.extract_cookie_names_from_headers(headers)
        
        for cookie in tmpCookies:
            if(cookie not in self.cookies):
                self.cookies.add(cookie)
                if cookie not in self.cookie_states:
                    self.cookie_states[cookie] = True  # Default state is enabled
            self.update_cookie_list()       

    def removeCookies(self, headers, body, messageInfo):
        cookie_header = self.get_cookie_header(headers)
        if(cookie_header == None):
            return None

        new_cookie_header = 'Cookie: '
        cookies_str = re.sub(r'Cookie: ', '', cookie_header, flags=re.IGNORECASE)
        cookie_pairs = cookies_str.split(';')
        request_needs_changed = False
        for pair in cookie_pairs:
            wasRemoved = False
            match = re.match(r'^\s*([^=]+?)\s*=\s*(.*?)\s*$', pair)
            if(match):
                cookie_name = match.group(1)
                if(cookie_name in self.cookies and not self.cookie_states[cookie_name]):
                    wasRemoved = True
                    request_needs_changed = True
            if(not wasRemoved):
                new_cookie_header = new_cookie_header + pair + '; '

        if(not request_needs_changed):
            return None

        # Create a new list of headers without the Cookie header
        updatedHeaders = []
        tmpIndex = 0
        cookieIndex = -1
        for header in headers:
            if(not header.lower().startswith("cookie:")):
                updatedHeaders.append(header)
            else:
                cookieIndex = tmpIndex
            tmpIndex += 1

        # Shouldn't ever happen as if there is no cookie header, we shouldn't get this far
        if(cookieIndex == -1):
            return None
        
        updatedHeaders.insert(cookieIndex, new_cookie_header)        

        request = messageInfo.getRequest()
        analyzed_request = self.helpers.analyzeRequest(request)

        requestText = self.helpers.bytesToString(messageInfo.getRequest())
        headers, body = requestText.split('\r\n\r\n', 1)
        requestLines = requestText.split('\r\n')

        # First line appears to be included in headers
        #newRequest = requestLines[0] + '\r\n'
        newRequest = '\r\n'.join(updatedHeaders) + '\r\n\r\n'
        newRequest += body

        if (self.debug):
            fH = open("C:\\tmp\\cookie-disabler.log", "a")
            fH.write("Original Request\n=======================================\n")
            fH.write(re.sub("\r?\n\r?\n", '\n\n', requestText))
            fH.write("---END---\n")
            fH.write("New Request\n=======================================\n")
            fH.write(newRequest)
            fH.write("---END---\n")
            fH.write("\n\n\n\n\n\n\n\n\n\n")
            fH.close()

        try:
            return self.helpers.stringToBytes(newRequest)
            #messageInfo.setRequest(self.helpers.stringToBytes(newRequest))
        except Exception as e:
            print(e)
    
    def get_cookie_header(self, headers):
        cookie_header = None
        for header in headers:
            if header.lower().startswith("cookie:"):
                cookie_header = header
                break
        return cookie_header

    def extract_cookie_names_from_headers(self, headers):
        cookie_header = self.get_cookie_header(headers)
        
        tmpCookies = set()
        if cookie_header:
            cookies_str = re.sub(r'Cookie: ', '', cookie_header, flags=re.IGNORECASE)
            cookie_pairs = cookies_str.split(';')
            for pair in cookie_pairs:
                cookie = pair.strip()
                cookie = re.sub(r'=.*', '', cookie)
                tmpCookies.add(cookie)
        return tmpCookies
    
    def getTabCaption(self):
        return "Cookie Capture"
    
    def getUiComponent(self):
        return self.panel
    
    def enable_selected(self, event):
        selected_cookies = self.cookie_jlist.getSelectedValuesList()
        self.toggle_cookies(selected_cookies, True)
    
    def disable_selected(self, event):
        selected_cookies = self.cookie_jlist.getSelectedValuesList()
        self.toggle_cookies(selected_cookies, False)
    
    def toggle_cookies(self, argCookies, enable):
        for cookie in argCookies:
            cookie = re.sub(r'\s*-\s+\S+\s*$', '', cookie)
            print(cookie, "toggled")
            self.cookie_states[cookie] = enable
        self.update_cookie_list()
    
    def search_cookies(self, event):
        query = self.search_field.getText().strip()
        if query:
            filtered_cookies = [cookie for cookie in self.cookies if re.search(query, cookie, re.IGNORECASE)]
        else:
            filtered_cookies = self.cookies
        self.update_cookie_list(filtered_cookies)
    
    def update_cookie_list(self, tmpCookies=None):
        self.cookie_list.clear()
        tmpCookies = tmpCookies or self.cookies
        for cookie in sorted(tmpCookies):
            state_indicator = "Enabled" if self.cookie_states[cookie] else "Disabled"
            self.cookie_list.addElement(cookie + " - " + state_indicator)
    

    