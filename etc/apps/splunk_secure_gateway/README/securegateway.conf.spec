[setup]
spacebridge_server = <ASCII string>
* Set the address of the Spacebridge Service
* Default: prod.spacebridge.spl.mobi

log_level = ERROR|WARN|INFO|DEBUG
* This controls the log_level for application logs
* If you need more detailed logs set to DEBUG
* Default: INFO

async_timeout = <positive_integer>
* Set the request timeout in seconds seen at the async request level
* Default: 15

cluster_monitor_interval = <positive_integer>
* This setting controls the interval in which the Search Head will query if it is the Captain in a SHC
* The Splunk Secure Gateway currently processes all requests through the Captain in a SHC
* Default: 300
* Remove?

cluster_mode_enabled = <boolean>
* Enable cluster mode.  If enabled, the modular inputs will run on every member of the SHC.
  Disabled, it will only run on the captain.
* Default: false
* Is this used?

mtls = <boolean>
* Enable Mutual TLS mode.  This is an advanced experimental feature and should not be adjusted without explicit
  instruction from Splunk.
* Default: false

[client]
request_timeout_secs = <positive_integer>
* Set the request timeout in seconds seen at the client level
* Default: 30

[websocket]
reconnect_max_delay = <positive_integer>
* When a websocket disconnects reconnection code retries with exponential back-off to a maximum value
* The reconnect_max_delay is the maximum reconnection delay in seconds
* Default: 60

[subscription]
manager_lifetime_seconds = <positive_integer>
* The subscription_manager_modular_input will run for a period defined by the manager_lifetime_seconds configuration
  before restarting the process
* Default: 3600

manager_interval_seconds = <positive_number>
* The subscription_manager_modular_input will poll new subscription requests from clients at an interval defined by the
  manage_interval_seconds
* If the Search Head instance is not performant this may be an option to reduce API calls to the host.
* Default: 0.1

[dashboard]
dashboard_list_max_count = <positive_integer>
* The dashboard_list_max_count setting will limit the number of dashboards returned in the dashboard list API
* If the dashboard list is timing out on clients this a helpful setting to limit the returned dashboards
* This is primarily a setting you would set while debugging an issue
* Default: 10000

[proxyConfig]
http_proxy = <string>
* If set, Splunk Secure Gateway App sends all HTTP requests through the proxy server that you specify.
* No Default.  Example formats:
* http_proxy = http://user:password@proxyIP:proxyPort
* http_proxy = user:password@proxyIp:proxyPort,
* http_proxy = http://proxyIp:proxyPort
* http_proxy = proxyIp:proxyPort

https_proxy = <string>
* If set, Splunk Secure Gateway App sends all HTTPS requests through the proxy server that you specify.
* No default.  Example formats:
* https_proxy = https://user:password@proxyIP:proxyPort
* https_proxy = user:password@proxyIp:proxyPort,
* https_proxy = https://proxyIp:proxyPort
* https_proxy = proxyIp:proxyPort

[registration]
* If set, allows registration attempts for a particular user to be validated using a webhook service.
* If this service returns a 200 status code, registration will continue. Otherwise registration will fail.
* The username is passed as a query parameter to the webhook as a GET request. Example formats:
registration_webhook_url = <string>
webhook_verify_ssl = <string>
