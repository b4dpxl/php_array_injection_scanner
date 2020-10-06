from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from array import array

import random
import string

ARRAY_TO = "Array to "
B_ARRAY_TO = bytearray(ARRAY_TO)
CONVERSION_IN = " conversion in"
B_CONVERSION_IN = bytearray(CONVERSION_IN)

NAME = "PHP Array Injection Scanner"


def fix_exception(func):
    def wrapper(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except Exception as e:
            print('*** PYTHON EXCEPTION: ' + str(e))
            raise
    return wrapper


class BurpExtender(IBurpExtender, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(NAME)

        self._canary = ''.join(random.choice(string.ascii_lowercase) for c in range(10))


        # register ourselves as a custom scanner check
        callbacks.registerScannerCheck(self)

    # helper method to search a response for occurrences of a literal match string
    # and return a list of start/end offsets

    def _get_matches(self, response, match_start, match_end=''):
        matches = []
        start = 0
        reslen = len(response)
        matchlen = len(match_end)
        while start < reslen:
            start = self._helpers.indexOf(response, match_start, False, start, reslen)
            if start == -1:
                break
            if match_end:
                end = self._helpers.indexOf(response, match_end, False, start, reslen)
                if end == -1:
                    break
            else:
                end = start + len(match_start)

            matches.append(array('i', [start, end + matchlen]))
            start = end + matchlen

        return matches

    #
    # implement IScannerCheck
    #

    def doPassiveScan(self, baseRequestResponse):
        return None

    @fix_exception
    def doActiveScan(self, baseRequestResponse, insertionPoint):
        # make a request containing our injection test in the insertion point
        if insertionPoint.getInsertionPointType() in [insertionPoint.INS_PARAM_URL, insertionPoint.INS_PARAM_BODY]:

            if self._helpers.urlDecode(insertionPoint.getInsertionPointName()).endswith("[]"):
                # already an array; ignore
                print("Ignoring " + insertionPoint.getInsertionPointName())
                return None

            originalResp = self._helpers.analyzeResponse(baseRequestResponse.getResponse())
            originalRespBody = baseRequestResponse.getResponse()[originalResp.getBodyOffset():]

            # create the base IScanIssue object
            scanIssue = PHPArrayScanIssue(
                            baseRequestResponse.getHttpService(),
                            self._helpers.analyzeRequest(baseRequestResponse).getUrl()
            )

            ## test conversting a parameter to a single array
            oldParam = self._helpers.buildParameter(
                insertionPoint.getInsertionPointName(),
                insertionPoint.getBaseValue(),
                insertionPoint.getInsertionPointType()
            )
            newRequest = self._helpers.removeParameter(baseRequestResponse.getRequest(), oldParam)

            # grab a copy of the request without the parameter, for comparison later
            noParamRequestResponse = self._callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), 
                newRequest
            )
            noParamResp = self._helpers.analyzeResponse(noParamRequestResponse.getResponse())
            noParamRespBody = noParamRequestResponse.getResponse()[noParamResp.getBodyOffset():]

            # insert the arrayified parameter
            newParam = self._helpers.buildParameter(
                insertionPoint.getInsertionPointName() + "[]",
                insertionPoint.getBaseValue(),
                insertionPoint.getInsertionPointType()
            )
            newRequest = self._helpers.addParameter(newRequest, newParam)
            # re-get the _actual_ parameter from the request (for highlighting)
            newParam = self._helpers.getRequestParameter(newRequest, insertionPoint.getInsertionPointName() + "[]")

            # make the new request
            newRequestResponse = self._callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), 
                newRequest
            )
            newResp = self._helpers.analyzeResponse(newRequestResponse.getResponse())
            newResponseBody = newRequestResponse.getResponse()[newResp.getBodyOffset():]
            
            ### check status codes
            if originalResp.getStatusCode() != newResp.getStatusCode():
                # print("Status codes don't match")
                scanIssue.setHttpMessages(
                    [self._callbacks.applyMarkers(
                        newRequestResponse, 
                        [array('i', [newParam.getNameStart(), newParam.getValueEnd()])], 
                        None
                    )]
                )
                scanIssue.setIssueDetail(
                    "Submitting an array parameter into '" + insertionPoint.getInsertionPointName() + 
                    "' returned the status code " + str(newResp.getStatusCode())
                )
                return [scanIssue]


            ### check for "array to XYZ conversion"
            matches = self._get_matches(newRequestResponse.getResponse(), B_ARRAY_TO, B_CONVERSION_IN)
            if len(matches):
                # report the issue
                scanIssue.setHttpMessages(
                    [self._callbacks.applyMarkers(
                        newRequestResponse, 
                        [array('i', [newParam.getNameStart(), newParam.getValueEnd()])], 
                        matches
                    )]
                )
                scanIssue.setIssueDetail(
                    "Submitting an array parameter into '" + insertionPoint.getInsertionPointName() + 
                    "' returned the string '" + ARRAY_TO + " ... " + CONVERSION_IN + "'"
                )
                return [scanIssue]

            ### check for straight differences between the original, no parameter, and arrayified requests
            if originalRespBody != newResponseBody and noParamRespBody != newResponseBody:
                scanIssue.setHttpMessages(
                    [
                        baseRequestResponse,
                        noParamRequestResponse,
                        self._callbacks.applyMarkers(
                            newRequestResponse, 
                            [array('i', [newParam.getNameStart(), newParam.getValueEnd()])], 
                            None
                        )
                    ]
                )
                scanIssue.setIssueDetail(
                    "Submitting an array parameter into '" + insertionPoint.getInsertionPointName() + 
                    "' returned a different response body to the original request"
                )
                scanIssue.setConfidence("Tentative")
                return [scanIssue]
            elif noParamRespBody == newResponseBody:
                print("original != array but no_param == array")

            ## test adding a secondary parameter
    
            newParam2 = self._helpers.buildParameter(
                insertionPoint.getInsertionPointName() + "[]",
                self._canary,
                insertionPoint.getInsertionPointType()
            )
            newRequest = self._helpers.addParameter(newRequest, newParam2)

            newRequestResponse = self._callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), 
                newRequest
            )
            newResp = self._helpers.analyzeResponse(newRequestResponse.getResponse())
            newResponseBody = newRequestResponse.getResponse()[newResp.getBodyOffset():]

            ### check status codes
            if originalResp.getStatusCode() != newResp.getStatusCode():
                scanIssue.setHttpMessages(
                    [self._callbacks.applyMarkers(
                        newRequestResponse, 
                        [array('i', [newParam.getNameStart(), newParam.getValueEnd() + len(self._canary) + 4 + len(insertionPoint.getInsertionPointName())])],
                        None
                    )]
                )
                scanIssue.setIssueDetail(
                    "Submitting a second array parameter into '" + insertionPoint.getInsertionPointName() + 
                    "' returned the status code " + str(newResp.getStatusCode())
                )
                return [scanIssue]

            ### check for "array to XYZ conversion"
            matches = self._get_matches(newRequestResponse.getResponse(), bytearray(self._canary))
            if len(matches):
                scanIssue.setHttpMessages(
                    [self._callbacks.applyMarkers(
                        newRequestResponse, 
                        [array('i', [newParam.getNameStart(), newParam.getValueEnd() + len(self._canary) + 4 + len(insertionPoint.getInsertionPointName())])],
                        matches
                    )]
                )
                scanIssue.setIssueDetail(
                    "Submitting a second array parameter into '" + insertionPoint.getInsertionPointName() + 
                    "' returned the string '" + self._canary + "'",
                )
                return [scanIssue]

            ### check for straight differences between the original and new requests
            if originalRespBody != newResponseBody and noParamRespBody != newResponseBody:
                scanIssue.setHttpMessages(
                    [
                        baseRequestResponse,
                        noParamRequestResponse,
                        self._callbacks.applyMarkers(
                            newRequestResponse, 
                            [array('i', [newParam.getNameStart(), newParam.getValueEnd() + len(self._canary) + 4 + len(insertionPoint.getInsertionPointName())])],
                            None
                        )
                    ]
                )
                scanIssue.setIssueDetail(
                    "Submitting a second array parameter into '" + insertionPoint.getInsertionPointName() + 
                    "' returned a different response body to the original request"
                )
                scanIssue.setConfidence("Tentative")
                return [scanIssue]
            elif noParamRespBody == newResponseBody:
                print("original != array but no_param == array")

        return None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName() and existingIssue.getIssueDetail() == newIssue.getIssueDetail():
            return -1

        return 0

class PHPArrayScanIssue (IScanIssue):

    def __init__(self, httpService, url, httpMessages = None, detail = None):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._detail = detail
        self._confidence = "Firm"



    def getUrl(self):
        return self._url

    def getIssueName(self):
        return "PHP Array Injection"

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return "Low"

    def getConfidence(self):
        return self._confidence

    def setConfidence(self, confidence):
        self._confidence = confidence

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def setIssueDetail(self, detail):
        self._detail = detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def setHttpMessages(self, httpMessages):
        self._httpMessages = httpMessages

    def getHttpService(self):
        return self._httpService