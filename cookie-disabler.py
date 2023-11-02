from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
from burp import ITab
from javax.swing import JList, DefaultListModel, JScrollPane, JPanel, JButton, BoxLayout, JTextField
from java.awt import BorderLayout, Container, Dimension, GridLayout
from java.nio import ByteBuffer
import time
import array

import re

class BurpExtender(IBurpExtender, IHttpListener, IProxyListener, ITab):
    cookies = set()
    headers = set()

    def registerExtenderCallbacks(self, callbacks):
        self.debug = False
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName("Cookie Disabler")
        self.cookie_states = {}  # Dictionary to store the state of each cookie
        self.header_states = {}  # Dictionary to store the state of each header
        
        self.setupUI()
        callbacks.registerHttpListener(self)        
        callbacks.registerProxyListener(self)

    def setupUI(self):
        # Create the main GUI
        self.panel = JPanel()
        self.panel.setLayout(GridLayout(1,2))
        #self.panel.setLayout(BorderLayout(10, 10))
        
        self.setupCookieUI()
        self.setupHeadersUI()
        
        self.callbacks.customizeUiComponent(self.panel)
        self.callbacks.addSuiteTab(self)
    
    def setupCookieUI(self):
        self.cookie_panel = JPanel()
        self.cookie_panel.setLayout(BorderLayout(10, 10))

        # Create a search field
        search_panel = JPanel()
        self.search_field = JTextField(20, actionPerformed=self.search_cookies)
        search_panel.add(self.search_field)
        self.cookie_panel.add(search_panel, BorderLayout.PAGE_START)
        
        # Main Cookie panel
        self.cookie_list = DefaultListModel()
        self.cookie_jlist = JList(self.cookie_list)
        self.cookie_scroll = JScrollPane(self.cookie_jlist)
        self.cookie_panel.add(self.cookie_scroll, BorderLayout.CENTER)
        
        self.enable_button = JButton("Enable Selected", actionPerformed=self.enable_selected_cookies)
        self.disable_button = JButton("Disable Selected", actionPerformed=self.disable_selected_cookies)
        
        button_panel = JPanel()
        button_panel.add(self.enable_button)
        button_panel.add(self.disable_button)
        self.cookie_panel.add(button_panel, BorderLayout.PAGE_END)
        self.panel.add(self.cookie_panel)
    
    def setupHeadersUI(self):
        self.header_panel = JPanel()
        self.header_panel.setLayout(BorderLayout(10, 10))

        # Create a search field
        search_panel = JPanel()
        self.header_search_field = JTextField(20, actionPerformed=self.search_headers)
        search_panel.add(self.header_search_field)
        self.header_panel.add(search_panel, BorderLayout.PAGE_START)
        
        # Main headers panel
        self.header_list = DefaultListModel()
        self.header_jlist = JList(self.header_list)
        self.header_scroll = JScrollPane(self.header_jlist)
        self.header_panel.add(self.header_scroll, BorderLayout.CENTER)
        
        self.enable_header_button = JButton("Enable Selected", actionPerformed=self.enable_selected_headers)
        self.disable_header_button = JButton("Disable Selected", actionPerformed=self.disable_selected_headers)
        
        button_panel = JPanel()
        button_panel.add(self.enable_header_button)
        button_panel.add(self.disable_header_button)
        self.header_panel.add(button_panel, BorderLayout.PAGE_END)

        self.panel.add(self.header_panel)

    def processProxyMessage(self, messageIsRequest, message):
        if messageIsRequest:
            # Modify the request here as needed
            original_request = message.getMessageInfo().getRequest()
            modified_request = self.modify_request(message.getMessageInfo(), original_request)
            if(modified_request == message.getMessageInfo().getRequest()):
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
        
        updatedRequest = self.removeCookies(requestString)
        updatedRequest = self.removeHeaders(updatedRequest)

        if (self.debug):
            fH = open("C:\\tmp\\cookie-disabler.log", "a")
            fH.write("Original Request\n=======================================\n")
            fH.write(requestString)
            fH.write("---END---\n")
            fH.write("New Request\n=======================================\n")
            fH.write(updatedRequest)
            fH.write("---END---\n")
            fH.write("\n\n\n\n\n\n\n\n\n\n")
            fH.close()

        updatedRequest = self.helpers.stringToBytes(updatedRequest)

        # Your modification logic here
        return updatedRequest
    
    # Grab any new cookies and store them to allow them to be toggled
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest or not toolFlag == self.callbacks.TOOL_PROXY:
            return
            
        requestInfo = self.helpers.analyzeRequest(messageInfo)
        headers = requestInfo.getHeaders()
        tmpCookies = self.extract_cookie_names_from_headers(headers)
        
        # Extract any unique cookies
        for cookie in tmpCookies:
            if(cookie not in self.cookies):
                self.cookies.add(cookie)
                if cookie not in self.cookie_states:
                    self.cookie_states[cookie] = True  # Default state is enabled
            self.update_cookie_list()

        # Extract any unique headers
        tmpHeaders = self.extract_header_names_from_headers(headers)
        for header in tmpHeaders:
            if(header not in self.headers):
                self.headers.add(header)
                if header not in self.header_states:
                    self.header_states[header] = True  # Default state is enabled
            self.update_header_list()       

    def get_headers(self, requestText):
        headersStr, body = requestText.split('\r\n\r\n', 1)
        headers = []
        for header in headersStr.split('\r\n'):
            headers.append(header)
        return headers

    def removeCookies(self, requestText):
        headers = self.get_headers(requestText)
        cookie_header = self.get_cookie_header(headers)
        if(cookie_header == None):
            return requestText

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
            return requestText

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
            return requestText
        
        updatedHeaders.insert(cookieIndex, new_cookie_header)        

        headers, body = requestText.split('\r\n\r\n', 1)
        newRequest = '\r\n'.join(updatedHeaders) + '\r\n\r\n'
        newRequest += body

        return newRequest
    
    def removeHeaders(self, requestText):
        headers = self.get_headers(requestText)
        # Create a new list of headers without the Cookie header
        headersChanged = False
        updatedHeaders = []
        for header in headers:
            header_name = re.sub(r':.*', '', header)
            if(header_name in self.headers and not self.header_states[header_name]):
                headersChanged = True
                continue
            else:
                updatedHeaders.append(header)
        
        if(not headersChanged):
            return requestText

        headers, body = requestText.split('\r\n\r\n', 1)
        newRequest = '\r\n'.join(updatedHeaders) + '\r\n\r\n'
        newRequest += body

        return newRequest
    
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

    def extract_header_names_from_headers(self, headers):
        if(not headers or len(headers) <= 1):
            return []

        tmpHeaders = []
        # Skip first request line, e.g. GET / HTTP/2
        for header in headers[1:]:
            header_name = re.sub(r':.*', '', header)
            tmpHeaders.append(header_name)
        
        return tmpHeaders
    
    def getTabCaption(self):
        return "Cookie Capture"
    
    def getUiComponent(self):
        return self.panel
    
    def enable_selected_cookies(self, event):
        selected_cookies = self.cookie_jlist.getSelectedValuesList()
        self.toggle_cookies(selected_cookies, True)
    
    def disable_selected_cookies(self, event):
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

    
    
    def enable_selected_headers(self, event):
        selected_headers = self.header_jlist.getSelectedValuesList()
        self.toggle_headers(selected_headers, True)
    
    def disable_selected_headers(self, event):
        selected_headers = self.header_jlist.getSelectedValuesList()
        self.toggle_headers(selected_headers, False)
    
    def toggle_headers(self, argHeaders, enable):
        for header in argHeaders:
            header = re.sub(r'\s*-\s+\S+\s*$', '', header)
            print(header, "toggled",str(enable))
            self.header_states[header] = enable
        self.update_header_list()
    
    def search_headers(self, event):
        query = self.header_search_field.getText().strip()
        if query:
            filtered_headers = [header for header in self.headers if re.search(query, header, re.IGNORECASE)]
        else:
            filtered_headers = self.headers
        self.update_header_list(filtered_headers)
    
    def update_header_list(self, tmpHeaders=None):
        self.header_list.clear()
        tmpHeaders = tmpHeaders or self.headers
        for header in sorted(tmpHeaders):
            state_indicator = "Enabled" if self.header_states[header] else "Disabled"
            self.header_list.addElement(header + " - " + state_indicator)
    

    