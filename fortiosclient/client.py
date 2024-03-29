# Copyright 2015 Fortinet, Inc.
#
# All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

import jinja2
try:
    from oslo_log import log as logging
except Exception:
    import logging

try:
    from oslo_serialization import jsonutils
except Exception:
    import json as jsonutils

from fortiosclient._i18n import _LE, _LW
from fortiosclient.common import constants as csts
from fortiosclient.common import singleton
from fortiosclient import eventlet_client
from fortiosclient import eventlet_request
from fortiosclient import exception
from fortiosclient import templates

LOG = logging.getLogger(__name__)


class FortiosApiClient(eventlet_client.EventletApiClient):
    """The FortiOS API Client."""

    def __init__(self, api_providers, user, password, token=None,
                 concurrent_connections=csts.DEFAULT_CONCURRENT_CONNECTIONS,
                 gen_timeout=csts.GENERATION_ID_TIMEOUT,
                 connect_timeout=csts.DEFAULT_CONNECT_TIMEOUT,
                 http_timeout=csts.DEFAULT_HTTP_TIMEOUT,
                 retries=csts.DEFAULT_RETRIES,
                 redirects=csts.DEFAULT_REDIRECTS,
                 singlethread=False):
        '''Constructor. Adds the following:
        :param api_providers: a list of tuples of the form: (host, port,
            is_ssl)
        :param http_timeout: how long to wait before aborting an
            unresponsive controller (and allow for retries to another
            controller in the cluster)
        :param retries: the number of http/https request to retry.
        :param redirects: the number of concurrent connections.
        '''
        super(FortiosApiClient, self).__init__(
            api_providers, user, password,
            concurrent_connections=concurrent_connections,
            gen_timeout=gen_timeout,
            connect_timeout=connect_timeout,
            singlethread=singlethread)

        self._request_timeout = http_timeout * retries
        self._http_timeout = http_timeout
        self._retries = retries
        self._redirects = redirects
        self._version = None
        self.message = {}
        self._user = user
        self._password = password
        self._token = token
        self._singlethread = singlethread

    @staticmethod
    def _render(template, **message):
        '''Render API message from it's template

        :param template: defined API message with essential params.
        :param message: It is a dictionary, included values of the params
                        for the template
        '''
        if not message:
            message = {}
        msg = jinja2.Template(template).render(**message)
        return jsonutils.loads(msg)

    def request(self, opt, content_type="application/json", **message):
        '''Issues request to controller.'''
        self.message = self._render(getattr(templates, opt), **message)
        method = self.message['method']
        url = self.message['path']
        body = self.message['body'] if 'body' in self.message else None
        g = eventlet_request.GenericRequestEventlet(
            self, method, url, body, content_type, auto_login=True,
            http_timeout=self._http_timeout,
            retries=self._retries, redirects=self._redirects,
            singlethread=self._singlethread)
        g.start()
        response = g.join()

        # response is a modified HTTPResponse object or None.
        # response.read() will not work on response as the underlying library
        # request_eventlet.ApiRequestEventlet has already called this
        # method in order to extract the body and headers for processing.
        # ApiRequestEventlet derived classes call .read() and
        # .getheaders() on the HTTPResponse objects and store the results in
        # the response object's .body and .headers data members for future
        # access.

        if response is None:
            # Timeout.
            LOG.error(_LE('Request timed out: %(method)s to %(url)s'),
                      {'method': method, 'url': url})
            raise exception.RequestTimeout()

        status = response.status
        if status == 401:
            raise exception.UnAuthorizedRequest()
        # Fail-fast: Check for exception conditions and raise the
        # appropriate exceptions for known error codes.
        if status in [404]:
            LOG.warning(_LW("Resource not found. Response status: %(status)s, "
                            "response body: %(response.body)s"),
                        {'status': status, 'response.body': response.body})
            exception.ERROR_MAPPINGS[status](response)
        elif status in exception.ERROR_MAPPINGS:
            LOG.error(_LE("Received error code: %s"), status)
            LOG.error(_LE("Server Error Message: %s"), response.body)
            exception.ERROR_MAPPINGS[status](response)

        # Continue processing for non-error condition.
        if (status != 200 and status != 201
                and status != 204):
            LOG.error(_LE("%(method)s to %(url)s, unexpected response code: "
                        "%(status)d (content = '%(body)s')"),
                      {'method': method, 'url': url,
                       'status': response.status, 'body': response.body})
            return None

        if url == jsonutils.loads(templates.LOGOUT)['path']:
            return response.body
        else:
            try:
                return jsonutils.loads(response.body)
            except UnicodeDecodeError:
                LOG.debug("The following strings cannot be decoded with "
                          "'utf-8, trying 'ISO-8859-1' instead. %(body)s",
                          {'body': response.body})
                return jsonutils.loads(response.body, encoding='ISO-8859-1')
            except Exception as e:
                LOG.error(_LE("Decode error, the response.body %(body)s"),
                          {'body': response.body})
                raise e
