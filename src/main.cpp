#if defined(ESP8266)
#include <ESP8266WiFi.h>
#else
#include <WiFi.h>
#endif

#include <DNSServerCP.h>
#include <ESPAsyncWebServer.h>

#define HOSTNAME "wifi.manager.net"

const char HTML[] =
    "<!DOCTYPE html>"
    "<html>"
        "<head>"
            "<meta name='viewport' content='width=device-width,initial-scale=1, user-scalable=no'/>"
            "<title>Captive Portal</title>"
        "</head>"
        "<body>"
            "<div class='main'>"
                "Hello captive portal"
            "</div>"
        "</body>"
    "</html>";

AsyncWebServer web_server(80);
DNSServerCP dns_server;

void redirect(AsyncWebServerRequest *request)
{
    String redirect_address = "http://" HOSTNAME;

    AsyncWebServerResponse *response = request->beginResponse(307);
    response->addHeader("X-Frame-Options", "deny");
    response->addHeader("Cache-Control", "no-cache");
    response->addHeader("Pragma", "no-cache");
    response->addHeader("Location", redirect_address);
    request->send(response);
}

bool redirectToCaptivePortal(AsyncWebServerRequest *request)
{
    if (request->host() != HOSTNAME && request->host() != WiFi.softAPIP().toString()) {
        redirect(request);
        return true;
    } else {
        return false;
    }
}

void setup()
{
    Serial.begin(115200);
    WiFi.disconnect(true);
    yield();
    delay(100);
    WiFi.mode(WIFI_AP);
    yield();
    delay(100);

    WiFi.softAPsetHostname(HOSTNAME);
    WiFi.softAP("Captive Portal");
    yield();
    delay(100);
    Serial.printf("Access Point started, IP: %s\n", WiFi.softAPIP().toString().c_str());
    web_server.on("/", HTTP_GET, [](AsyncWebServerRequest *request) {
        if (!redirectToCaptivePortal(request)) {
            request->send(200, "text/html", HTML);
        }
    });
    web_server.onNotFound([](AsyncWebServerRequest *request) {
        redirect(request);
    });

    web_server.begin();
    dns_server.start(53, "*", WiFi.softAPIP());
    dns_server.setTTL(0);
}

void loop()
{
    dns_server.processNextRequest();
}
